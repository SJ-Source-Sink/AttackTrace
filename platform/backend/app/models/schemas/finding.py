"""
Finding request/response schemas.
"""

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


class FindingCommentResponse(BaseModel):
    id: str
    finding_id: str
    user_id: str
    body: str
    created_at: str
    updated_at: Optional[str] = None
    user_email: Optional[str] = None
    user_full_name: Optional[str] = None

    @classmethod
    def from_orm(cls, comment, user=None) -> "FindingCommentResponse":
        return cls(
            id=str(comment.id),
            finding_id=str(comment.finding_id),
            user_id=str(comment.user_id),
            body=comment.body,
            created_at=comment.created_at.isoformat(),
            updated_at=comment.updated_at.isoformat() if comment.updated_at else None,
            user_email=user.email if user else None,
            user_full_name=user.full_name if user else None,
        )


class FindingResponse(BaseModel):
    id: str
    org_id: str
    scan_job_id: Optional[str] = None
    asset_id: Optional[str] = None
    source: str = "attacktrace"
    source_scan_id: Optional[str] = None
    title: str
    description: str
    severity: str
    category: str
    affected_asset: str
    evidence: Optional[dict[str, Any]] = None
    remediation: str
    references: list[str]
    cve: list[str]
    cvss_score: Optional[float] = None
    status: str
    ai_severity: Optional[str] = None
    ai_reasoning: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_triaged_at: Optional[str] = None
    false_positive: bool
    suppressed: bool
    suppressed_reason: Optional[str] = None
    suppressed_until: Optional[str] = None
    ticket_ref: Optional[str] = None
    comment_count: int = 0
    created_at: str
    updated_at: str

    # KEV / EPSS / confidence
    confidence: Optional[str] = None
    kev_status: bool = False
    epss_score: Optional[float] = None
    priority_score: Optional[float] = None

    # Frontend-compatible aliases
    scan_id: str = ""
    organization_id: str = ""
    asset_value: str = ""
    asset_type: Optional[str] = None
    cve_id: Optional[str] = None
    remediation_steps: list[str] = []
    ai_triage: Optional[dict[str, Any]] = None
    first_seen: str = ""
    last_seen: str = ""
    age_days: int = 0
    tags: list[str] = []
    assigned_to: Optional[str] = None
    accept_risk_info: Optional[dict[str, Any]] = None
    comments: list[dict[str, Any]] = []

    @classmethod
    def from_orm(cls, finding, comment_count: int = 0) -> "FindingResponse":
        created_at_str = finding.created_at.isoformat()
        now = datetime.now(timezone.utc)
        created = finding.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (now - created).days

        cve_list = finding.cve or []
        remediation_steps = [s.strip() for s in finding.remediation.split("\n") if s.strip()] if finding.remediation else []

        ai_triage = None
        if finding.ai_severity:
            ai_triage = {
                "severity": finding.ai_severity.value,
                "reasoning": finding.ai_reasoning or "",
                "confidence": int(finding.ai_confidence * 100) if finding.ai_confidence else 0,
                "suggested_remediation": finding.remediation or "",
                "false_positive_likelihood": int(finding.ai_confidence * 30) if finding.ai_confidence else 0,
                "business_impact": "",
            }

        return cls(
            id=str(finding.id),
            org_id=str(finding.org_id),
            scan_job_id=str(finding.scan_job_id) if finding.scan_job_id else None,
            asset_id=str(finding.asset_id) if finding.asset_id else None,
            source=getattr(finding, "source", "attacktrace") or "attacktrace",
            source_scan_id=getattr(finding, "source_scan_id", None),
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value,
            category=finding.category,
            affected_asset=finding.affected_asset,
            evidence=finding.evidence,
            remediation=finding.remediation,
            references=finding.references or [],
            cve=cve_list,
            cvss_score=finding.cvss_score,
            status=finding.status.value,
            ai_severity=finding.ai_severity.value if finding.ai_severity else None,
            ai_reasoning=finding.ai_reasoning,
            ai_confidence=finding.ai_confidence,
            ai_triaged_at=finding.ai_triaged_at.isoformat() if finding.ai_triaged_at else None,
            false_positive=finding.false_positive,
            suppressed=finding.suppressed,
            suppressed_reason=finding.suppressed_reason,
            suppressed_until=finding.suppressed_until.isoformat() if finding.suppressed_until else None,
            ticket_ref=finding.ticket_ref,
            comment_count=comment_count,
            created_at=created_at_str,
            updated_at=finding.updated_at.isoformat(),
            # KEV / EPSS / confidence
            confidence=getattr(finding, "confidence", None),
            kev_status=getattr(finding, "kev_status", False) or False,
            epss_score=getattr(finding, "epss_score", None),
            priority_score=getattr(finding, "priority_score", None),
            # Frontend-compatible aliases
            scan_id=str(finding.scan_job_id) if finding.scan_job_id else "",
            organization_id=str(finding.org_id),
            asset_value=finding.affected_asset or "",
            asset_type=None,
            cve_id=cve_list[0] if cve_list else None,
            remediation_steps=remediation_steps,
            ai_triage=ai_triage,
            first_seen=created_at_str,
            last_seen=finding.updated_at.isoformat(),
            age_days=age_days,
            tags=[],
            assigned_to=None,
            accept_risk_info=None,
            comments=[],
        )


class FindingCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    severity: str  # critical / high / medium / low / info
    category: str = ""
    affected_asset: str = ""
    description: str = ""
    evidence: Optional[dict[str, Any]] = None
    remediation: str = ""
    references: list[str] = []
    cve: list[str] = []
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    status: str = "open"
    ticket_ref: Optional[str] = None


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    false_positive: Optional[bool] = None
    suppressed: Optional[bool] = None
    suppressed_reason: Optional[str] = None
    suppressed_until: Optional[datetime] = None
    ticket_ref: Optional[str] = None
    remediation: Optional[str] = None

    def validate_status(self) -> Optional[str]:
        valid = {"open", "in_progress", "remediated", "accepted_risk", "false_positive"}
        if self.status and self.status not in valid:
            raise ValueError(f"Status must be one of: {valid}")
        return self.status


class FindingCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


class FindingFilter(BaseModel):
    scan_job_id: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    category: Optional[str] = None
    search: Optional[str] = None
    asset_id: Optional[str] = None
    false_positive: Optional[bool] = None
    suppressed: Optional[bool] = None
    has_cve: Optional[bool] = None
    min_cvss: Optional[float] = None
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=200)
