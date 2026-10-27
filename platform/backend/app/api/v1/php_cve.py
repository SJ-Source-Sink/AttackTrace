"""
PHP2Shell scanner — CVE-2026-109618 / CVE-2026-109619 (unauthenticated PHP RCE).

Give it IPs, CIDRs or hostnames; it fingerprints PHP on each web port and flags
hosts running a vulnerable (or possibly vulnerable) PHP. Detection logic and the
reasoning behind its verdicts live in app.services.php2shell.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, AsyncGenerator
from uuid import UUID

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dashboard import invalidate_dashboard_cache
from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.asset import Asset, AssetType
from app.models.db.org import Organization
from app.models.db.user import User
from app.services import php2shell as p2s
from app.services.finding_ingest import ingest_findings

router = APIRouter(prefix="/php-cve", tags=["PHP2Shell Scanner"])

# ── Filesystem history (same shape as the other scanners) ─────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "php_cve" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_history_path(org_id: str, scan_id: str) -> Path:
    if not _UUID_RE.match(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan_id: must be a UUID")
    base = _history_dir(org_id)
    candidate = (base / f"{scan_id}.json").resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise HTTPException(status_code=400, detail="Invalid scan_id")
    return candidate


def _save_scan_result(org_id: str, record: dict) -> None:
    try:
        (_history_dir(org_id) / f"{record['id']}.json").write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
    try:
        files = sorted(_history_dir(org_id).glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)[:limit]
    except Exception:
        return []
    out = []
    for f in files:
        try:
            out.append(json.loads(f.read_text()))
        except Exception:
            pass
    return out


# ── Findings ──────────────────────────────────────────────────────────────────

# status -> (severity, base confidence). Confidence is capped by what a banner
# can prove: the version is read straight from the host, but whether the build
# carries a backport is invisible from outside.
_STATUS_SEVERITY = {
    "vulnerable": "critical",
    "likely_vulnerable": "high",
    "unverified": "medium",
    "version_hidden": "medium",
}
_STATUS_TITLE = {
    "vulnerable": "PHP2Shell: vulnerable PHP version (CVE-2026-109618 / CVE-2026-109619)",
    "likely_vulnerable": "PHP2Shell: end-of-life PHP, likely vulnerable (CVE-2026-109618 / CVE-2026-109619)",
    "unverified": "PHP2Shell: PHP version below fix, vendor backport unverified (CVE-2026-109618 / CVE-2026-109619)",
    "version_hidden": "PHP2Shell: PHP detected, version hidden — exposure cannot be determined",
}


def _confidence(status: str, source: str | None) -> str:
    if status == "vulnerable":
        return "high" if source == "phpinfo" else "medium"
    if status == "likely_vulnerable":
        return "medium" if source == "phpinfo" else "low"
    return "low"


def host_to_findings(h: dict[str, Any]) -> list[dict]:
    """Normalise one fingerprinted host into zero or more ingestable findings."""
    out: list[dict] = []
    a = h.get("assessment") or {}
    status = a.get("status")
    name = h["label"].split(" (")[0]
    asset = f"{h['scheme']}://{f'[{name}]' if ':' in name else name}:{h['port']}"
    evidence = {
        "oracle": "bare-signal" if status in ("unverified", "version_hidden") else "extracted-value",
        "php_version": h.get("version"),
        "version_source": h.get("version_source"),
        "branch": a.get("branch"),
        "fixed_in": a.get("fixed_in"),
        "distro_hint": h.get("distro"),
        "sapi": h.get("sapi"),
        "server_header": h.get("server_header"),
        "x_powered_by": h.get("powered_by"),
        "signals": h.get("signals"),
        "session_upload_progress": h.get("upload_progress"),
        "memory_limit": h.get("memory_limit"),
        "fatal_error_backtraces": h.get("fatal_error_backtraces"),
        "ip": h.get("ip"),
        "port": h.get("port"),
    }
    evidence = {k: v for k, v in evidence.items() if v not in (None, [], "")}

    if status in _STATUS_SEVERITY:
        desc = a.get("reason", "")
        if h.get("version"):
            desc = f"PHP {h['version']} (read from {h.get('version_source')}). {desc}"
        desc += (
            " CVE-2026-109618 (memory corruption on request setup / upload-progress unserializer) and "
            "CVE-2026-109619 (use-after-free of state surviving into a later request) are unauthenticated "
            "RCE (CVSS v4 9.2), exploited in the wild and on CISA KEV since 2026-10-26. This is a version "
            "assessment: no exploit was sent, because the only known triggers are memory-corrupting requests."
        )
        if h.get("upload_progress") == "On":
            desc += " phpinfo() shows session.upload_progress.enabled=On, a confirmed attack path."
        out.append({
            "title": _STATUS_TITLE[status],
            "description": desc,
            "severity": _STATUS_SEVERITY[status],
            "category": "php-rce",
            "affected_asset": asset,
            "evidence": evidence,
            "remediation": p2s.REMEDIATION,
            "references": p2s.REFERENCES,
            "cve": p2s.CVES,
            "cvss_score": p2s.CVSS,
            "kev_status": True,
            "confidence": _confidence(status, h.get("version_source")),
        })

    if h.get("phpinfo_url"):
        out.append({
            "title": "phpinfo() page publicly exposed",
            "description": (
                f"{h['phpinfo_url']} serves phpinfo(), disclosing the exact PHP version, build, SAPI, "
                "loaded modules, configuration and environment. It makes exploit targeting (such as "
                "PHP2Shell) far more reliable."
            ),
            "severity": "medium",
            "category": "php-info-disclosure",
            "affected_asset": asset,
            "evidence": {k: v for k, v in {
                "oracle": "extracted-value", "phpinfo_url": h["phpinfo_url"],
                "php_version": h.get("version"), "sapi": h.get("sapi"),
            }.items() if v},
            "remediation": "Delete the phpinfo() file from production, or restrict it to trusted networks/authentication.",
            "confidence": "certain",
        })
    return out


# ── Scan generator ────────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


async def _run_scan(
    targets_raw: list[str],
    ports: list[int],
    probe_phpinfo: bool,
    org_id: str,
    scan_id: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()
    allow_private = bool(_get_settings().ALLOW_PRIVATE_SCAN_TARGETS)
    targets, errors = await p2s.expand_targets(targets_raw, allow_private)
    total = len(targets) * len(ports)
    yield _sse("start", {"scan_id": scan_id, "total_hosts": len(targets), "total": total,
                         "ports": ports, "errors": errors})

    results: list[dict] = []
    findings: list[dict] = []
    checked = 0
    sem = asyncio.Semaphore(25)

    async with p2s.make_client() as client:
        async def one(t: p2s.Target, port: int):
            async with sem:
                try:
                    return t, port, await p2s.fingerprint(client, t, port, probe_phpinfo)
                except Exception:
                    return t, port, None

        tasks = [asyncio.create_task(one(t, port)) for t in targets for port in ports]
        try:
            for fut in asyncio.as_completed(tasks):
                t, port, res = await fut
                checked += 1
                if res is not None:
                    d = res.to_dict()
                    results.append(d)
                    yield _sse("host_result", d)
                    for f in host_to_findings(d):
                        findings.append(f)
                        yield _sse("finding", {**f, "host": d["label"], "port": d["port"]})
                yield _sse("progress", {"checked": checked, "total": total, "current": f"{t.label}:{port}"})
        finally:
            for task in tasks:
                task.cancel()

    def count(status: str) -> int:
        return sum(1 for r in results if (r.get("assessment") or {}).get("status") == status)

    summary = {
        "scan_id": scan_id,
        "total_hosts": len(targets),
        "web_services": len(results),
        "php_services": sum(1 for r in results if r.get("php_detected")),
        "vulnerable": count("vulnerable"),
        "likely_vulnerable": count("likely_vulnerable"),
        "unverified": count("unverified"),
        "version_hidden": count("version_hidden"),
        "patched": count("patched"),
        "not_affected": count("not_affected"),
        "phpinfo_exposed": sum(1 for r in results if r.get("phpinfo_url")),
        "errors": errors,
    }
    yield _sse("complete", summary)

    _save_scan_result(org_id, {
        "id": scan_id,
        "target": ", ".join(targets_raw)[:200],
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "ports": ports,
        "summary": summary,
        "scanned_targets": [{"ip": t.ip, "host": t.host_header or t.ip} for t in targets],
        "results": results,
        "findings": findings,
    })
    if findings:
        try:
            await ingest_findings(db, org_id, source="php2shell", source_scan_id=scan_id, findings=findings)
            await db.commit()
            await invalidate_dashboard_cache(org_id)
        except Exception:
            await db.rollback()


# ── Routes ────────────────────────────────────────────────────────────────────

class PhpScanRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=2048,
                               description="IPs, CIDR ranges or hostnames")
    ports: list[int] = Field(default_factory=lambda: list(p2s.DEFAULT_PORTS), max_length=p2s.MAX_PORTS)
    probe_phpinfo: bool = True


@router.get("/advisory", summary="PHP2Shell advisory facts used by the scanner")
async def advisory(current_user: Annotated[User, Depends(get_current_user)]) -> dict:
    return {
        "cves": p2s.CVES,
        "cvss": p2s.CVSS,
        "fixed_versions": [f"{a}.{b}.{p}" for (a, b), p in sorted(p2s.FIXED_PATCH.items())],
        "backport_only_branches": ["7.4", "8.0", "8.1"],
        "no_fix_branches": "5.4 – 7.3",
        "kev": True,
        "references": p2s.REFERENCES,
        "default_ports": p2s.DEFAULT_PORTS,
        "max_hosts": p2s.MAX_HOSTS,
    }


@router.post("/scan", summary="Scan IPs/hosts for PHP2Shell (CVE-2026-109618/109619) exposure")
async def run_scan(
    payload: PhpScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    # Accept newline/comma/space separated entries inside list items too.
    raw = [t for entry in payload.targets for t in re.split(r"[\s,;]+", entry) if t]
    if not raw:
        raise HTTPException(status_code=422, detail="at least one target is required")
    ports = sorted({p for p in payload.ports if 1 <= p <= 65535})
    if not ports:
        raise HTTPException(status_code=422, detail="at least one valid port (1-65535) is required")
    scan_id = str(_uuid_mod.uuid4())
    from app.services.scan_activity import tee_scan_activity
    return StreamingResponse(
        tee_scan_activity(org_id, "php2shell", ", ".join(raw)[:200], scan_id, _run_scan(
            targets_raw=raw, ports=ports, probe_phpinfo=payload.probe_phpinfo,
            org_id=str(org_id), scan_id=scan_id, db=db,
        )),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/history", summary="List previous PHP2Shell scans")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    limit: int = 50,
) -> dict:
    items = [{
        "id": r["id"], "target": r.get("target", ""),
        "started_at": r.get("started_at"), "completed_at": r.get("completed_at"),
        "summary": r.get("summary", {}),
    } for r in _load_history(str(org_id), limit=limit)]
    return {"items": items, "total": len(items)}


@router.get("/history/{scan_id}", summary="Get a previous PHP2Shell scan")
async def get_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    path = _safe_history_path(str(org_id), scan_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    return json.loads(path.read_text())


@router.delete("/history/{scan_id}", summary="Delete a previous PHP2Shell scan")
async def delete_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    path = _safe_history_path(str(org_id), scan_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    path.unlink()
    return {"deleted": True}


# ── Asset picker + report ─────────────────────────────────────────────────────

_PICKER_TYPES = {"ip", "domain", "subdomain", "webapp"}


def _asset_target(asset_type: str, value: str) -> str | None:
    """The scannable host for an inventory asset (webapp URLs -> hostname)."""
    v = (value or "").strip()
    if asset_type == "webapp":
        v = urlparse(v if "://" in v else f"//{v}").hostname or ""
    v = v.strip().rstrip(".")
    if not v or "*" in v or " " in v or "/" in v:
        return None
    return v


@router.get("/assets", summary="Discovered assets that can be added as scan targets")
async def list_scannable_assets(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    types: str = Query("ip,domain,subdomain,webapp", description="comma-separated asset types"),
    search: str | None = Query(None, max_length=200),
    active_only: bool = True,
    limit: int = Query(5000, ge=1, le=10000),
) -> dict:
    wanted = [t for t in (x.strip().lower() for x in types.split(",")) if t in _PICKER_TYPES]
    if not wanted:
        raise HTTPException(status_code=422, detail="no valid asset types")
    q = select(Asset).where(Asset.org_id == org_id, Asset.asset_type.in_([AssetType(t) for t in wanted]))
    if active_only:
        q = q.where(Asset.is_active.is_(True))
    if search:
        q = q.where(Asset.value.ilike(f"%{search.replace('%', '').replace('_', '')}%"))
    q = q.order_by(Asset.risk_score.desc().nulls_last(), Asset.value).limit(limit + 1)
    rows = (await db.execute(q)).scalars().all()
    truncated = len(rows) > limit
    items, seen = [], set()
    for a in rows[:limit]:
        t = _asset_target(a.asset_type.value, a.value)
        if not t or t.lower() in seen:
            continue
        seen.add(t.lower())
        items.append({"id": str(a.id), "value": a.value, "asset_type": a.asset_type.value,
                      "target": t, "risk_score": a.risk_score})
    return {"items": items, "total": len(items), "truncated": truncated, "max_scan_hosts": p2s.MAX_HOSTS}


async def _inventory_for(db: AsyncSession, org_id: str, record: dict) -> dict[str, dict]:
    keys: set[str] = set()
    for t in record.get("scanned_targets", []):
        keys.update({str(t.get("host", "")).lower(), str(t.get("ip", "")).lower()})
    for r in record.get("results", []):
        keys.update({r["label"].split(" (")[0].lower(), str(r.get("ip", "")).lower()})
    keys.discard("")
    if not keys:
        return {}
    res = await db.execute(select(Asset).where(Asset.org_id == org_id, func.lower(Asset.value).in_(list(keys))))
    inv: dict[str, dict] = {}
    for a in res.scalars().all():
        inv.setdefault(a.value.lower(), {"asset_type": a.asset_type.value, "risk_score": a.risk_score})
    return inv


@router.get("/history/{scan_id}/report", summary="Download a PHP2Shell scan report (html, pdf or csv)")
async def scan_report(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    fmt: str = Query("html", pattern="^(html|pdf|csv)$"),
) -> Response:
    from app.services import php2shell_report as rep
    path = _safe_history_path(str(org_id), scan_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    record = json.loads(path.read_text())
    inventory = await _inventory_for(db, str(org_id), record)
    rows = rep.build_rows(record, inventory)
    name = f"php2shell-report-{scan_id[:8]}"
    if fmt == "csv":
        return Response(rep.render_csv(rows), media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={name}.csv"})
    org_name = (await db.execute(select(Organization.name).where(Organization.id == org_id))).scalar_one_or_none() or ""
    html = rep.render_html(record, rows, org_name, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    if fmt == "html":
        return Response(html, media_type="text/html",
                        headers={"Content-Disposition": f"attachment; filename={name}.html"})
    from app.services.export_service import html_to_pdf_bytes
    return Response(await html_to_pdf_bytes(html), media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={name}.pdf"})
