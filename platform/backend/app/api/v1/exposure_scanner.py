"""
Exposed Files Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Checks a target URL for accidentally exposed sensitive files:
version control, env files, backups, configs, credentials, logs, cloud secrets.
"""

from __future__ import annotations

import json
import re
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.core.remediation import get_remediation
from app.models.db.user import User
from app.api.v1.dashboard import invalidate_dashboard_cache
from app.services.finding_ingest import ingest_findings

# ── Filesystem history ────────────────────────────────────────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "exposure_scanner" / org_id
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
    try:
        path = _history_dir(org_id) / f"{record['id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
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


router = APIRouter(prefix="/exposure", tags=["Exposure Scanner"])

# ── Path definitions ──────────────────────────────────────────────────────────

EXPOSED_PATHS: dict[str, list[str]] = {
    "version_control": [
        "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/index",
        "/.git/packed-refs", "/.gitignore", "/.svn/entries", "/.svn/wc.db",
        "/.hg/hgrc", "/.bzr/branch/format",
    ],
    "environment_files": [
        "/.env", "/.env.local", "/.env.production", "/.env.staging", "/.env.backup",
        "/.env.example", "/config/.env", "/app/.env", "/.env.old",
    ],
    "backup_files": [
        "/backup.sql", "/backup.sql.gz", "/db.sql", "/database.sql", "/dump.sql",
        "/backup.tar.gz", "/backup.zip", "/site.tar.gz", "/www.tar.gz",
        "/backup.bak", "/backup.old", "/index.php.bak", "/wp-config.php.bak",
        "/config.php.bak", "/database.bak",
    ],
    "config_files": [
        "/config.php", "/config.yml", "/config.yaml", "/config.json", "/config.xml",
        "/configuration.php", "/app/config.php", "/settings.py", "/settings.json",
        "/web.config", "/application.yml", "/application.properties",
        "/docker-compose.yml", "/docker-compose.yaml", "/.docker/config.json",
        "/Jenkinsfile", "/.travis.yml", "/.circleci/config.yml", "/.github/workflows/deploy.yml",
        "/Dockerfile", "/.dockerignore",
    ],
    "credentials": [
        "/wp-config.php", "/wp-config-sample.php",
        "/credentials.json", "/credentials.xml", "/credentials.yml",
        "/secrets.yml", "/secrets.json", "/secrets.yaml",
        "/.ssh/id_rsa", "/.ssh/id_ecdsa", "/.ssh/authorized_keys",
        "/server.key", "/private.key", "/cert.key",
        "/id_rsa", "/id_dsa",
    ],
    "debug_info": [
        "/phpinfo.php", "/info.php", "/php.php", "/test.php",
        "/adminer.php", "/phpmyadmin/", "/pma/",
        "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/.well-known/openid-configuration", "/.well-known/jwks.json",
        "/api-docs", "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    ],
    "logs": [
        "/error.log", "/access.log", "/debug.log", "/app.log", "/server.log",
        "/logs/error.log", "/var/log/apache2/error.log", "/storage/logs/laravel.log",
    ],
    "cloud": [
        "/.aws/credentials", "/.aws/config",
        "/.gcloud/credentials.json",
        "/service-account.json", "/gcloud.json",
    ],
}

# ── Severity classification ───────────────────────────────────────────────────

_CRITICAL_PATTERNS = {
    "/.git/config", "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.backup", "/config/.env", "/app/.env", "/.env.old",
    "/credentials.json", "/credentials.xml", "/credentials.yml",
    "/secrets.yml", "/secrets.json", "/secrets.yaml",
    "/wp-config.php", "/backup.sql", "/backup.sql.gz", "/db.sql",
    "/database.sql", "/dump.sql",
    "/.ssh/id_rsa", "/.ssh/id_ecdsa", "/.ssh/authorized_keys",
    "/server.key", "/private.key", "/cert.key", "/id_rsa", "/id_dsa",
    "/.aws/credentials", "/.aws/config", "/.gcloud/credentials.json",
    "/service-account.json", "/gcloud.json",
}

_HIGH_PATTERNS = {
    "/phpinfo.php", "/info.php", "/php.php", "/adminer.php",
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/docker-compose.yml", "/docker-compose.yaml", "/.docker/config.json",
    "/.github/workflows/deploy.yml", "/.travis.yml", "/.circleci/config.yml",
    "/Jenkinsfile",
}

_MEDIUM_PATTERNS = {
    "/config.yml", "/config.yaml", "/config.json", "/config.xml",
    "/configuration.php", "/settings.py", "/settings.json",
    "/web.config", "/application.yml", "/application.properties",
    "/Dockerfile", "/.dockerignore",
    "/error.log", "/access.log", "/debug.log", "/app.log", "/server.log",
    "/logs/error.log", "/storage/logs/laravel.log",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/backup.tar.gz", "/backup.zip", "/site.tar.gz", "/www.tar.gz",
    "/backup.bak", "/backup.old", "/index.php.bak", "/wp-config.php.bak",
    "/config.php.bak", "/database.bak",
    "/config.php", "/app/config.php", "/.svn/entries", "/.svn/wc.db",
    "/.hg/hgrc", "/.bzr/branch/format",
    "/api-docs",
}

_INFO_PATTERNS = {
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt", "/.gitignore",
    "/test.php", "/pma/", "/phpmyadmin/",
    "/wp-config-sample.php",
    "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/index", "/.git/packed-refs",
}


def _classify_severity(path: str) -> str:
    if path in _CRITICAL_PATTERNS:
        return "critical"
    if path in _HIGH_PATTERNS:
        return "high"
    if path in _INFO_PATTERNS:
        return "info"
    if path in _MEDIUM_PATTERNS:
        return "medium"
    # fallback: extension heuristics
    lp = path.lower()
    if any(lp.endswith(ext) for ext in (".key", ".pem", ".p12", ".pfx")):
        return "critical"
    if any(lp.endswith(ext) for ext in (".log", ".bak", ".old", ".backup")):
        return "medium"
    if any(lp.endswith(ext) for ext in (".sql", ".gz", ".tar", ".zip")):
        return "high"
    return "medium"


# ── SSE helper ────────────────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


# ── Core scan generator ───────────────────────────────────────────────────────

def _adapt_exposure_findings(findings: list[dict]) -> list[dict]:
    """Normalize exposure_scanner.py findings for finding_ingest.

    Confidence reflects the actual oracle: a 200 with real content returned is
    a direct extracted-value proof ("certain"); a 403 only proves the path
    exists, not that it's exploitable ("low" — a lead, not a confirmation).
    """
    adapted = []
    for f in findings:
        status_code = f.get("status_code")
        confidence = "certain" if status_code == 200 else "low"
        adapted.append({
            "title": f"Exposed: {f.get('path', 'unknown path')}",
            "description": f.get("note", ""),
            "severity": f.get("severity", "medium"),
            "category": f"exposure-{f.get('category', 'unknown')}",
            "affected_asset": f.get("url", ""),
            "evidence": {"status_code": status_code, "size_bytes": f.get("size_bytes"),
                         "content_preview": f.get("content_preview")},
            "remediation": get_remediation(category=f.get("category")),
            "confidence": confidence,
        })
    return adapted


async def _run_exposure_scan(
    target: str,
    check_git: bool,
    check_env: bool,
    check_backups: bool,
    check_configs: bool,
    check_credentials: bool,
    check_debug: bool,
    check_logs: bool,
    check_cloud: bool,
    custom_paths: list[str],
    db: AsyncSession,
    org_id: str | None = None,
) -> AsyncGenerator[str, None]:
    scan_id = str(_uuid_mod.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    base = target.rstrip("/")

    # Build path list based on enabled categories
    category_map = {
        "version_control":  check_git,
        "environment_files": check_env,
        "backup_files":     check_backups,
        "config_files":     check_configs,
        "credentials":      check_credentials,
        "debug_info":       check_debug,
        "logs":             check_logs,
        "cloud":            check_cloud,
    }

    paths_to_check: list[tuple[str, str]] = []  # (path, category)
    for category, enabled in category_map.items():
        if enabled:
            for p in EXPOSED_PATHS[category]:
                paths_to_check.append((p, category))

    for cp in custom_paths:
        if cp.strip():
            paths_to_check.append((cp.strip() if cp.startswith("/") else "/" + cp.strip(), "custom"))

    total = len(paths_to_check)
    yield _sse("start", {"target": base, "total_paths": total, "scan_id": scan_id})

    findings: list[dict] = []
    checked = 0

    async with httpx.AsyncClient(
        timeout=5.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (AttackTrace Exposure Scanner)"},
    ) as client:
        for path, category in paths_to_check:
            checked += 1
            url = f"{base}{path}"

            yield _sse("progress", {
                "checked": checked,
                "total": total,
                "current_path": path,
            })

            try:
                resp = await client.get(url)

                if resp.status_code == 200 and len(resp.content) > 0:
                    severity = _classify_severity(path)
                    content_preview = resp.text[:200] if resp.text else ""
                    finding = {
                        "path": path,
                        "url": str(resp.url),
                        "status_code": 200,
                        "severity": severity,
                        "category": category,
                        "size_bytes": len(resp.content),
                        "content_preview": content_preview,
                        "note": "File accessible",
                    }
                    findings.append(finding)
                    yield _sse("finding", finding)

                elif resp.status_code == 403:
                    finding = {
                        "path": path,
                        "url": url,
                        "status_code": 403,
                        "severity": "medium",
                        "category": category,
                        "size_bytes": 0,
                        "content_preview": "",
                        "note": "Path exists but access denied (may be bypassable)",
                    }
                    findings.append(finding)
                    yield _sse("finding", finding)

            except httpx.TimeoutException:
                pass
            except Exception:
                pass

    # Summarize
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    by_category: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "medium")
        if sev in by_severity:
            by_severity[sev] += 1
        cat = f.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    complete_data = {
        "scan_id": scan_id,
        "target": base,
        "total_checked": checked,
        "total_found": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }
    yield _sse("complete", complete_data)

    # Persist
    if org_id:
        _save_scan_result(org_id, {
            "id":           scan_id,
            "target":       base,
            "started_at":   started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "total_checked": checked,
            "total_found":   len(findings),
            "by_severity":   by_severity,
            "by_category":   by_category,
            "findings":      findings,
        })
        try:
            adapted = _adapt_exposure_findings(findings)
            await ingest_findings(db, org_id, source="exposure_scanner", source_scan_id=scan_id, findings=adapted)
            await db.commit()
            await invalidate_dashboard_cache(org_id)
        except Exception:
            await db.rollback()


# ── Request model ─────────────────────────────────────────────────────────────

class ExposureScanRequest(BaseModel):
    target: str
    check_git: bool = True
    check_env: bool = True
    check_backups: bool = True
    check_configs: bool = True
    check_credentials: bool = True
    check_debug: bool = True
    check_logs: bool = True
    check_cloud: bool = True
    custom_paths: list[str] = []


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/scan", summary="Scan a target URL for exposed sensitive files")
async def run_exposure_scan(
    payload: ExposureScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    if not payload.target.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target is required",
        )
    raw = payload.target.strip()
    normalized = raw if raw.startswith(("http://", "https://")) else f"https://{raw}"
    return StreamingResponse(
        _run_exposure_scan(
            target=normalized,
            check_git=payload.check_git,
            check_env=payload.check_env,
            check_backups=payload.check_backups,
            check_configs=payload.check_configs,
            check_credentials=payload.check_credentials,
            check_debug=payload.check_debug,
            check_logs=payload.check_logs,
            check_cloud=payload.check_cloud,
            custom_paths=payload.custom_paths,
            org_id=str(org_id),
            db=db,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/history", summary="List previous exposure scans for this org")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    limit: int = 50,
) -> dict:
    records = _load_history(str(org_id), limit=limit)
    items = []
    for r in records:
        items.append({
            "id":            r["id"],
            "target":        r["target"],
            "started_at":    r.get("started_at"),
            "completed_at":  r.get("completed_at"),
            "total_checked": r.get("total_checked", 0),
            "total_found":   r.get("total_found", 0),
            "by_severity":   r.get("by_severity", {}),
            "by_category":   r.get("by_category", {}),
        })
    return {"items": items, "total": len(items)}


@router.get("/history/{scan_id}", summary="Get full details of a previous exposure scan")
async def get_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a previous exposure scan record")
async def delete_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    if not _delete_scan(str(org_id), scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}
