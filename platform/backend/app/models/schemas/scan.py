"""
Scan job request/response schemas and SSE event models.
"""

import math
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class ScanCreate(BaseModel):
    target_domains: list[str] = Field(min_length=1)
    company_name: Optional[str] = None
    workspace_id: Optional[str] = None
    intensity: str = "passive"
    modules_to_skip: list[str] = Field(default_factory=list)
    scheduled_at: Optional[datetime] = None
    schedule_cron: Optional[str] = None

    @field_validator("intensity")
    @classmethod
    def validate_intensity(cls, v: str) -> str:
        valid = {"passive", "normal", "aggressive"}
        if v not in valid:
            raise ValueError(f"Intensity must be one of: {valid}")
        return v

    @field_validator("target_domains")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        cleaned = []
        for domain in v:
            domain = domain.strip().lower()
            if not domain:
                continue
            cleaned.append(domain)
        if not cleaned:
            raise ValueError("At least one valid domain is required")
        return cleaned


class FindingsCountSchema(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResponse(BaseModel):
    id: str
    org_id: str
    workspace_id: Optional[str] = None
    target_domains: list[str]
    company_name: Optional[str] = None
    intensity: str
    status: str
    modules_to_skip: list[str]
    session_id: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    results_summary: Optional[dict] = None
    findings_count: Optional[FindingsCountSchema] = None
    scheduled_at: Optional[str] = None
    schedule_cron: Optional[str] = None
    celery_task_id: Optional[str] = None
    created_at: str
    updated_at: str

    @classmethod
    def from_orm(cls, job) -> "ScanResponse":
        fc = job.findings_count or {}
        return cls(
            id=str(job.id),
            org_id=str(job.org_id),
            workspace_id=str(job.workspace_id) if job.workspace_id else None,
            target_domains=job.target_domains or [],
            company_name=job.company_name,
            intensity=job.intensity.value,
            status=job.status.value,
            modules_to_skip=job.modules_to_skip or [],
            session_id=job.session_id,
            started_at=job.started_at.isoformat() if job.started_at else None,
            completed_at=job.completed_at.isoformat() if job.completed_at else None,
            error_message=job.error_message,
            results_summary=job.results_summary,
            findings_count=FindingsCountSchema(**fc) if fc else None,
            scheduled_at=job.scheduled_at.isoformat() if job.scheduled_at else None,
            schedule_cron=job.schedule_cron,
            celery_task_id=job.celery_task_id,
            created_at=job.created_at.isoformat(),
            updated_at=job.updated_at.isoformat(),
        )


class ScanProgressEvent(BaseModel):
    """SSE event payload for scan progress streaming."""
    event_type: str  # module_start | module_complete | finding | status_change | error | complete
    scan_id: str
    timestamp: str
    data: dict[str, Any]

    def to_sse(self) -> str:
        """Format as SSE wire format."""
        import json
        payload = json.dumps(self.model_dump())
        return f"data: {payload}\n\n"


class ScanListFilter(BaseModel):
    status: Optional[str] = None
    workspace_id: Optional[str] = None
    target_domain: Optional[str] = None
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=200)
