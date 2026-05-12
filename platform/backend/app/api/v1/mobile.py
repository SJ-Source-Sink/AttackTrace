"""
Mobile Security Scanner API — self-contained, no external sidecar.
"""

import csv
import io
import json
import logging
import os
import re
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.mobile import MobileFinding, MobilePattern, MobileScan
from app.models.db.user import User

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/mobile", tags=["Mobile Scanner"])

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
_ALLOWED_EXTENSIONS = {".apk", ".apkm", ".xapk", ".ipa", ".jar", ".exe", ".dll"}
_MAX_FILE_SIZE = 500 * 1024 * 1024


def _upload_dir() -> Path:
    d = Path(settings.MOBILE_UPLOAD_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _platform_from_ext(ext: str) -> str:
    return {".apk": "android", ".apkm": "android", ".xapk": "android",
            ".ipa": "ios", ".jar": "jar", ".exe": "exe", ".dll": "exe"}.get(ext.lower(), "android")


def _scan_to_dict(scan: MobileScan) -> dict:
    return {
        "scan_id": str(scan.id),
        "apk": scan.app_name,
        "platform": scan.platform,
        "package": scan.package_id,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "created_at": int(scan.created_at.timestamp()) if scan.created_at else 0,
        "severity_counts": scan.findings_count or {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
        "total_findings": sum((scan.findings_count or {}).values()),
    }


def _finding_to_dict(f: MobileFinding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "description": f.description or "",
        "remediation": f.remediation or "",
        "cwe": f.cwe or "",
        "triage_status": f.triage_status,
        "evidence": {"file": f.file_path or "", "line": f.line_number, "snippet": f.code_snippet or ""},
    }


def _pattern_to_dict(p: MobilePattern) -> dict:
    return {
        "id": str(p.id),
        "title": p.title,
        "platform": p.platform,
        "severity": p.severity,
        "category": p.category,
        "description": p.description or "",
        "remediation": p.remediation or "",
        "cwe": p.cwe or "",
        "patterns": [{"pattern": p.regex_pattern}],
        "enabled": p.is_enabled,
        "source": "custom" if p.is_custom else "builtin",
    }


@router.get("/health")
async def mobile_health():
    return {"status": "ok", "engine": "local", "msra_reachable": True}


@router.get("/stats")
async def mobile_stats(db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    total = (await db.execute(select(func.count()).select_from(MobileScan).where(MobileScan.org_id == org_id))).scalar() or 0
    completed = (await db.execute(select(func.count()).select_from(MobileScan).where(MobileScan.org_id == org_id, MobileScan.status == "completed"))).scalar() or 0
    scans = (await db.execute(select(MobileScan).where(MobileScan.org_id == org_id).order_by(MobileScan.created_at.desc()).limit(20))).scalars().all()
    return {
        "total_scans": total, "completed_scans": completed,
        "total_findings": sum(sum((s.findings_count or {}).values()) for s in scans),
        "recent_scans": [_scan_to_dict(s) for s in scans],
    }


@router.get("/scans")
async def list_scans(db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    scans = (await db.execute(select(MobileScan).where(MobileScan.org_id == org_id).order_by(MobileScan.created_at.desc()).limit(50))).scalars().all()
    return [_scan_to_dict(s) for s in scans]


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_app(file: UploadFile = File(...), db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id), _user: User = Depends(get_current_user)):
    if not file.filename:
        raise HTTPException(400, "No filename provided")
    ext = Path(file.filename).suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported file type '{ext}'")
    scan_id = uuid4()
    save_path = _upload_dir() / f"{scan_id}_{file.filename}"
    total = 0
    with open(save_path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > _MAX_FILE_SIZE:
                out.close(); os.unlink(save_path)
                raise HTTPException(413, "File exceeds 500 MB limit")
            out.write(chunk)
    platform = _platform_from_ext(ext)
    scan = MobileScan(id=scan_id, org_id=org_id, app_name=file.filename, platform=platform, status="pending",
                      file_path=str(save_path), findings_count={"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}, progress=0, message="Queued...")
    db.add(scan); await db.commit(); await db.refresh(scan)
    try:
        from app.workers.mobile_worker import run_mobile_scan
        task = run_mobile_scan.apply_async(args=[str(scan_id)], queue="scans")
        scan.celery_task_id = task.id; await db.commit()
    except Exception as e:
        logger.warning(f"Failed to dispatch mobile scan task: {e}")
    return {"scan_id": str(scan_id), "status": "pending", "platform": platform}


@router.get("/scans/{scan_id}/status")
async def scan_status(scan_id: UUID, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    scan = (await db.execute(select(MobileScan).where(MobileScan.id == scan_id, MobileScan.org_id == org_id))).scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    return {"status": scan.status, "progress": scan.progress, "message": scan.message or "", "error": scan.error_message}


@router.get("/scans/{scan_id}/findings")
async def scan_findings(scan_id: UUID, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    scan = (await db.execute(select(MobileScan).where(MobileScan.id == scan_id, MobileScan.org_id == org_id))).scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    findings = sorted((await db.execute(select(MobileFinding).where(MobileFinding.scan_id == scan_id))).scalars().all(),
                      key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.id))
    return {
        "scan_id": str(scan_id), "apk": scan.app_name, "package": scan.package_id or "",
        "platform": scan.platform, "status": scan.status,
        "scan_time": (scan.completed_at or scan.created_at).isoformat(),
        "total_findings": len(findings),
        "severity_counts": scan.findings_count or {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
        "risk_score": scan.risk_score, "findings": [_finding_to_dict(f) for f in findings],
    }


class TriageRequest(BaseModel):
    status: str


@router.patch("/scans/{scan_id}/findings/{finding_id}/triage")
async def triage_finding(scan_id: UUID, finding_id: int, body: TriageRequest, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    finding = (await db.execute(select(MobileFinding).join(MobileScan, MobileFinding.scan_id == MobileScan.id).where(MobileFinding.id == finding_id, MobileFinding.scan_id == scan_id, MobileScan.org_id == org_id))).scalar_one_or_none()
    if not finding: raise HTTPException(404, "Finding not found")
    finding.triage_status = body.status; await db.commit(); await db.refresh(finding)
    return _finding_to_dict(finding)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: UUID, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id), _user: User = Depends(get_current_user)):
    scan = (await db.execute(select(MobileScan).where(MobileScan.id == scan_id, MobileScan.org_id == org_id))).scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    if scan.file_path: Path(scan.file_path).unlink(missing_ok=True)
    await db.delete(scan); await db.commit()


@router.get("/scans/{scan_id}/export/{fmt}")
async def export_scan(scan_id: UUID, fmt: str, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    scan = (await db.execute(select(MobileScan).where(MobileScan.id == scan_id, MobileScan.org_id == org_id))).scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    findings = (await db.execute(select(MobileFinding).where(MobileFinding.scan_id == scan_id))).scalars().all()
    if fmt == "json":
        data = json.dumps({"scan": _scan_to_dict(scan), "findings": [_finding_to_dict(f) for f in findings]}, indent=2)
        return StreamingResponse(io.BytesIO(data.encode()), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=mobile_{scan_id}.json"})
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf); w.writerow(["ID","Title","Severity","Category","CWE","File","Line","Snippet","Triage"])
        for f in findings: w.writerow([f.id, f.title, f.severity, f.category, f.cwe or "", f.file_path or "", f.line_number or "", f.code_snippet or "", f.triage_status])
        return StreamingResponse(io.BytesIO(buf.getvalue().encode()), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=mobile_{scan_id}.csv"})
    if fmt == "sarif":
        sarif = {"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "AttackTrace Mobile Scanner", "version": "1.0"}}, "results": [{"ruleId": f.cwe or f.category, "level": {"Critical":"error","High":"error","Medium":"warning","Low":"note","Info":"none"}.get(f.severity,"warning"), "message": {"text": f.title}, "locations": [{"physicalLocation":{"artifactLocation":{"uri": f.file_path or "unknown"},"region":{"startLine": f.line_number or 1}}}] if f.file_path else []} for f in findings]}]}
        return StreamingResponse(io.BytesIO(json.dumps(sarif, indent=2).encode()), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=mobile_{scan_id}.sarif"})
    raise HTTPException(400, f"Unsupported format '{fmt}'. Use: json, csv, sarif")


@router.get("/rules/stats")
async def rules_stats(db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    patterns = (await db.execute(select(MobilePattern).where(or_(MobilePattern.org_id == org_id, MobilePattern.org_id == None)))).scalars().all()  # noqa: E711
    by_plat: dict = {}; by_sev: dict = {}; enabled = custom = 0
    for p in patterns:
        by_plat[p.platform] = by_plat.get(p.platform, 0) + 1
        by_sev[p.severity] = by_sev.get(p.severity, 0) + 1
        if p.is_enabled: enabled += 1
        if p.is_custom: custom += 1
    return {"total": len(patterns), "enabled": enabled, "disabled": len(patterns) - enabled, "by_source": {"builtin": len(patterns) - custom, "custom": custom}, "by_platform": by_plat, "by_severity": by_sev, "android": by_plat.get("android", 0), "ios": by_plat.get("ios", 0), "jar": by_plat.get("jar", 0), "exe": by_plat.get("exe", 0), "custom": custom}


@router.get("/rules")
async def list_rules(db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    patterns = (await db.execute(select(MobilePattern).where(or_(MobilePattern.org_id == org_id, MobilePattern.org_id == None)).order_by(MobilePattern.is_custom, MobilePattern.platform, MobilePattern.title))).scalars().all()  # noqa: E711
    return [_pattern_to_dict(p) for p in patterns]


class RuleCreate(BaseModel):
    title: str; platform: str; severity: str; category: str; pattern: str
    description: Optional[str] = None; remediation: Optional[str] = None; cwe: Optional[str] = None


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_rule(body: RuleCreate, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id), _user: User = Depends(get_current_user)):
    try: re.compile(body.pattern)
    except re.error as e: raise HTTPException(400, f"Invalid regex: {e}")
    p = MobilePattern(org_id=org_id, platform=body.platform, title=body.title, severity=body.severity, category=body.category, regex_pattern=body.pattern, description=body.description, remediation=body.remediation, cwe=body.cwe, is_custom=True, is_enabled=True)
    db.add(p); await db.commit(); await db.refresh(p)
    return _pattern_to_dict(p)


class RuleUpdate(BaseModel):
    title: Optional[str] = None; platform: Optional[str] = None; severity: Optional[str] = None
    category: Optional[str] = None; pattern: Optional[str] = None; description: Optional[str] = None
    remediation: Optional[str] = None; cwe: Optional[str] = None


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: UUID, body: RuleUpdate, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id), _user: User = Depends(get_current_user)):
    p = (await db.execute(select(MobilePattern).where(MobilePattern.id == rule_id))).scalar_one_or_none()
    if not p: raise HTTPException(404, "Rule not found")
    if not p.is_custom or p.org_id != org_id: raise HTTPException(403, "Cannot modify built-in rules")
    if body.pattern:
        try: re.compile(body.pattern)
        except re.error as e: raise HTTPException(400, f"Invalid regex: {e}")
        p.regex_pattern = body.pattern
    for field in ("title","platform","severity","category","description","remediation","cwe"):
        val = getattr(body, field)
        if val is not None: setattr(p, field, val)
    await db.commit(); await db.refresh(p)
    return _pattern_to_dict(p)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: UUID, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id), _user: User = Depends(get_current_user)):
    p = (await db.execute(select(MobilePattern).where(MobilePattern.id == rule_id))).scalar_one_or_none()
    if not p: raise HTTPException(404, "Rule not found")
    if not p.is_custom or p.org_id != org_id: raise HTTPException(403, "Cannot delete built-in rules")
    await db.delete(p); await db.commit()


@router.patch("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: UUID, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id), _user: User = Depends(get_current_user)):
    p = (await db.execute(select(MobilePattern).where(MobilePattern.id == rule_id, or_(MobilePattern.org_id == org_id, MobilePattern.org_id == None)))).scalar_one_or_none()  # noqa: E711
    if not p: raise HTTPException(404, "Rule not found")
    p.is_enabled = not p.is_enabled; await db.commit(); await db.refresh(p)
    return _pattern_to_dict(p)


@router.get("/scans/{scan_id}/findings/{finding_id}/snippet")
async def finding_snippet(scan_id: UUID, finding_id: int, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id)):
    f = (await db.execute(select(MobileFinding).join(MobileScan, MobileFinding.scan_id == MobileScan.id).where(MobileFinding.id == finding_id, MobileFinding.scan_id == scan_id, MobileScan.org_id == org_id))).scalar_one_or_none()
    if not f: raise HTTPException(404, "Finding not found")
    return {"snippet": f.code_snippet or "", "file": f.file_path or "", "line": f.line_number}


@router.get("/adb-devices")
async def adb_devices():
    return {"devices": [], "error": None}


@router.post("/scans/{scan_id}/dynamic")
async def start_dynamic(scan_id: UUID, _user: User = Depends(get_current_user)):
    return {"job_id": "not-supported", "status": "queued", "message": "Dynamic analysis requires ADB setup."}


@router.get("/dynamic/jobs")
async def list_dynamic_jobs():
    return []


@router.get("/dynamic/{job_id}")
async def dynamic_job(job_id: str):
    return {"job_id": job_id, "status": "not_found"}


class PocRequest(BaseModel):
    finding_id: int; scan_id: str


@router.post("/ai/poc")
async def generate_poc(body: PocRequest, db: AsyncSession = Depends(get_db), org_id: UUID = Depends(get_current_org_id), _user: User = Depends(get_current_user)):
    f = (await db.execute(select(MobileFinding).join(MobileScan, MobileFinding.scan_id == MobileScan.id).where(MobileFinding.id == body.finding_id, MobileScan.org_id == org_id))).scalar_one_or_none()
    if not f: raise HTTPException(404, "Finding not found")
    if not settings.ANTHROPIC_API_KEY:
        return {"poc_code": f"# PoC for: {f.title}\n# Severity: {f.severity} | CWE: {f.cwe or 'N/A'}\n\n# {f.description or ''}\n\n# Set ANTHROPIC_API_KEY to generate AI-powered PoC."}
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        msg = await client.messages.create(model="claude-haiku-4-5-20251001", max_tokens=1024, messages=[{"role":"user","content": f"Generate a concise proof-of-concept for this mobile security finding:\nTitle: {f.title}\nSeverity: {f.severity}\nCWE: {f.cwe or 'N/A'}\nDescription: {f.description or 'N/A'}\nSnippet: {f.code_snippet or 'N/A'}\n\nProvide practical demonstration steps with code."}])
        return {"poc_code": msg.content[0].text if msg.content else "# Could not generate PoC"}
    except Exception as e:
        return {"poc_code": f"# Generation failed: {e}"}


@router.post("/sync")
async def sync_findings():
    return {"inserted": 0, "updated": 0, "skipped": 0}
