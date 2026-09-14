"""
Reports API: generate HTML reports and retrieve them.
"""

import asyncio
import glob as glob_module
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User
from app.services.report_service import generate_report, generate_pdf_report, scan_id_belongs_to_org, is_safe_scan_id

router = APIRouter(prefix="/reports", tags=["Reports"])
settings = get_settings()


class ReportRequest(BaseModel):
    scan_job_id: str
    format: str = "html"
    include_evidence: bool = True


@router.get(
    "",
    summary="List previously generated reports for this org",
)
async def list_reports(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    scan_job_id: Optional[str] = None,
) -> dict:
    report_dir = Path(settings.ATTACKTRACE_WORKSPACE_DIR) / "reports" / str(org_id)
    if not report_dir.exists():
        return {"items": [], "total": 0}

    items = []
    for f in sorted(report_dir.glob("report_*.html"), key=lambda x: x.stat().st_mtime, reverse=True):
        # filename: report_{scan_job_id}_{YYYYMMDD}_{HHMMSS}.html
        parts = f.stem.split("_")
        if len(parts) < 2:
            continue
        file_scan_id = parts[1]  # UUID (hyphens, no underscores)
        if scan_job_id and file_scan_id != scan_job_id:
            continue
        stat = f.stat()
        items.append({
            "id": f.stem,
            "scan_id": file_scan_id,
            "name": f.name,
            "format": "html",
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })

    return {"items": items, "total": len(items)}


@router.post(
    "/generate",
    summary="Generate a security report for a completed scan",
    description=(
        "Generates an HTML report for a completed ScanJob. "
        "Uses AttackTrace's native HTML template when available, falling back to a built-in template. "
        "Returns metadata including the download path."
    ),
)
async def generate_report_endpoint(
    payload: ReportRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # scan_job_id may be a real ScanJob UUID or a standalone scanner's
    # non-UUID source_scan_id (e.g. nmap/secrets short-hex ids) — both are
    # valid report targets, so no upfront UUID validation here; generate_report
    # (via _load_scan_context) resolves either shape and raises ValueError
    # (-> 400 below) if nothing in this org matches at all.
    try:
        report_meta = await generate_report(
            db=db,
            scan_job_id=payload.scan_job_id,
            org_id=org_id,
            report_format=payload.format,
            include_evidence=payload.include_evidence,
            requester_user_id=current_user.id,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "REPORT_ERROR", "message": str(e)}},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": {"code": "REPORT_GENERATION_FAILED", "message": str(e)}},
        )

    return report_meta


@router.get(
    "/{scan_job_id}/download",
    summary="Download the HTML report for a scan",
    description="Streams the generated HTML report file.",
    response_class=FileResponse,
)
async def download_report(
    scan_job_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    # scan_job_id is loosely typed (str, not UUID) so standalone scanners'
    # non-UUID source_scan_id values (short hex, e.g. nmap/secrets) don't get
    # rejected with a 422 before this handler ever runs — FastAPI's automatic
    # UUID-path-param validation used to do exactly that. In exchange, this
    # handler must itself reject anything that isn't a safe filename/glob
    # component before touching the filesystem (path traversal guard).
    if not is_safe_scan_id(scan_job_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Scan not found"}},
        )

    # Serve an already-generated report straight from disk first, if one
    # exists. This intentionally comes BEFORE the DB ownership check below:
    # the report directory is already scoped to the caller's authenticated
    # org_id (reports/{org_id}/...), so a file found here is safe to serve
    # without re-verifying the underlying scan/findings still exist in the
    # DB. That matters because a report file can legitimately outlive its
    # source ScanJob/Finding rows (e.g. test-data cleanup, retention), and
    # previously such a stale-but-still-valid report would 404 even though
    # the exact same file downloaded fine when freshly generated.
    report_dir = Path(settings.ATTACKTRACE_WORKSPACE_DIR) / "reports" / str(org_id)
    # scan_job_id is now an arbitrary caller-supplied string (loosened from
    # UUID, see above) — glob.escape it so a value containing glob
    # metacharacters (*, ?, [...]) can't broaden the match beyond this exact
    # scan id, even within the caller's own org-scoped directory.
    existing_reports = sorted(
        report_dir.glob(f"report_{glob_module.escape(scan_job_id)}_*.html"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    ) if report_dir.exists() else []

    if existing_reports:
        existing_path = existing_reports[0]
        if await asyncio.to_thread(os.path.getsize, existing_path) > 0:
            return FileResponse(
                path=str(existing_path),
                filename=existing_path.name,
                media_type="text/html",
            )

    # No cached file — generating a fresh one needs live DB data, so only
    # now do we require the scan to still resolve to this org (prevents IDOR
    # via a guessed/foreign scan_job_id). "Scan" here may be an orchestrated
    # ScanJob or a standalone scanner run (cspm/secrets/etc.)
    if not await scan_id_belongs_to_org(db, scan_job_id, org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Scan not found or no report is available for it"}},
        )

    try:
        report_meta = await generate_report(
            db=db,
            scan_job_id=scan_job_id,
            org_id=org_id,
            report_format="html",
            include_evidence=True,
            requester_user_id=current_user.id,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "REPORT_ERROR", "message": str(e)}},
        )

    return FileResponse(
        path=report_meta["path"],
        filename=report_meta["filename"],
        media_type="text/html",
    )


@router.get(
    "/{scan_job_id}/pdf",
    summary="Download the PDF report for a scan",
    description="Converts the HTML report to PDF using weasyprint and streams it.",
    response_class=FileResponse,
)
async def download_pdf_report(
    scan_job_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    # scan_job_id is loosely typed (str, not UUID) — see download_report above
    # for why (non-UUID standalone-scanner source_scan_id values), and why it
    # must be validated as a safe filename/glob component before any
    # filesystem access.
    if not is_safe_scan_id(scan_job_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Scan not found"}},
        )

    # Serve an already-generated PDF straight from disk first, if one exists
    # — same rationale as download_report: the report directory is already
    # scoped to the caller's org, so this is safe without a DB ownership
    # re-check, and it covers PDFs whose source scan/findings have since been
    # deleted from the DB while the file itself still exists on disk.
    report_dir = Path(settings.ATTACKTRACE_WORKSPACE_DIR) / "reports" / str(org_id)
    # scan_job_id is now an arbitrary caller-supplied string — glob.escape it
    # (see download_report above for why).
    existing_pdfs = sorted(
        report_dir.glob(f"report_{glob_module.escape(scan_job_id)}_*.pdf"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    ) if report_dir.exists() else []

    if existing_pdfs:
        existing_pdf = existing_pdfs[0]
        if await asyncio.to_thread(os.path.getsize, existing_pdf) > 0:
            return FileResponse(
                path=str(existing_pdf),
                media_type="application/pdf",
                filename=f"report_{scan_job_id}.pdf",
                headers={"Content-Disposition": f"attachment; filename=report_{scan_job_id}.pdf"},
            )

    # No cached file — generating one needs live DB data, so only now do we
    # require the scan to still resolve to this org (prevents IDOR via a
    # guessed/foreign scan_job_id). "Scan" here may be an orchestrated
    # ScanJob or a standalone scanner run (cspm/secrets/etc.)
    if not await scan_id_belongs_to_org(db, scan_job_id, org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Scan not found or no report is available for it"}},
        )

    try:
        pdf_path = await generate_pdf_report(
            db=db,
            scan_job_id=scan_job_id,
            org_id=org_id,
            workspace_dir=settings.ATTACKTRACE_WORKSPACE_DIR,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "REPORT_ERROR", "message": str(e)}},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": {"code": "PDF_GENERATION_FAILED", "message": str(e)}},
        )

    if not pdf_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "PDF report not found"}},
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"report_{scan_job_id}.pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_job_id}.pdf"},
    )
