"""
Suppression Rules API.

Manage org-level suppression rules that automatically suppress matching findings
in future scans.
"""

import math
from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.suppression_rule import ScanSuppressionRule
from app.models.db.user import User

router = APIRouter(prefix="/suppression-rules", tags=["Suppression Rules"])


class SuppressionRuleCreate(BaseModel):
    finding_title: str
    affected_asset_pattern: str
    action: str  # 'false_positive' | 'accepted_risk' | 'suppress'
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None


class SuppressionRuleResponse(BaseModel):
    id: str
    org_id: str
    finding_title: str
    affected_asset_pattern: str
    action: str
    expires_at: Optional[str] = None
    created_by: Optional[str] = None
    created_at: str
    notes: Optional[str] = None

    @classmethod
    def from_orm(cls, rule: ScanSuppressionRule) -> "SuppressionRuleResponse":
        return cls(
            id=str(rule.id),
            org_id=str(rule.org_id),
            finding_title=rule.finding_title,
            affected_asset_pattern=rule.affected_asset_pattern,
            action=rule.action,
            expires_at=rule.expires_at.isoformat() if rule.expires_at else None,
            created_by=str(rule.created_by) if rule.created_by else None,
            created_at=rule.created_at.isoformat(),
            notes=rule.notes,
        )


@router.post(
    "",
    response_model=SuppressionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a suppression rule",
)
async def create_suppression_rule(
    payload: SuppressionRuleCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> SuppressionRuleResponse:
    valid_actions = {"false_positive", "accepted_risk", "suppress"}
    if payload.action not in valid_actions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_ACTION", "message": f"action must be one of {valid_actions}"}},
        )

    rule = ScanSuppressionRule(
        org_id=org_id,
        finding_title=payload.finding_title,
        affected_asset_pattern=payload.affected_asset_pattern,
        action=payload.action,
        expires_at=payload.expires_at,
        created_by=current_user.id,
        notes=payload.notes,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return SuppressionRuleResponse.from_orm(rule)


@router.get(
    "",
    summary="List suppression rules for the org",
)
async def list_suppression_rules(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
) -> dict:
    now = datetime.now(timezone.utc)
    base_query = select(ScanSuppressionRule).where(
        ScanSuppressionRule.org_id == org_id,
    )

    count_query = select(func.count()).select_from(base_query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    offset = (page - 1) * per_page
    result = await db.execute(
        base_query.order_by(ScanSuppressionRule.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    rules = result.scalars().all()
    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {
        "items": [SuppressionRuleResponse.from_orm(r).model_dump() for r in rules],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a suppression rule",
)
async def delete_suppression_rule(
    rule_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    result = await db.execute(
        select(ScanSuppressionRule).where(
            ScanSuppressionRule.id == rule_id,
            ScanSuppressionRule.org_id == org_id,
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "RULE_NOT_FOUND", "message": "Suppression rule not found"}},
        )
    await db.delete(rule)
