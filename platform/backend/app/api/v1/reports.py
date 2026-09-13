"""
Reports API: generate HTML reports and retrieve them.
"""

import asyncio
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
from app.services.report_service import generate_report, generate_pdf_report, scan_id_belongs_to_org

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
    try:
        scan_job_id = UUID(payload.scan_job_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "Invalid scan_job_id"}},
        )

    try:
        report_meta = await generate_report(
            db=db,
            scan_job_id=scan_job_id,
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
    scan_job_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    # Verify scan belongs to this org (prevents IDOR) — a "scan" here may be an
    # orchestrated ScanJob or a standalone scanner run (cspm/secrets/etc.)
    if not await scan_id_belongs_to_org(db, scan_job_id, org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Scan not found"}},
        )

    # Check if a report already exists for this scan to avoid redundant regeneration
    report_dir = Path(settings.ATTACKTRACE_WORKSPACE_DIR) / "reports" / str(org_id)
    existing_reports = sorted(
        report_dir.glob(f"report_{scan_job_id}_*.html"),
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
    scan_job_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    # Verify scan belongs to this org (prevents IDOR) — a "scan" here may be an
    # orchestrated ScanJob or a standalone scanner run (cspm/secrets/etc.)
    if not await scan_id_belongs_to_org(db, scan_job_id, org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": "Scan not found"}},
        )

    try:
        pdf_path = await generate_pdf_report(
            db=db,
            scan_job_id=str(scan_job_id),
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
