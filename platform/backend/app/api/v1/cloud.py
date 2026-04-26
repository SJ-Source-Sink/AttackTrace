"""
Cloud Asset Discovery API — uses cloudlist (projectdiscovery) to enumerate
cloud resources across AWS, GCP, and Azure.
"""

import asyncio
import json
import os
import shutil
import tempfile
from typing import Annotated
from uuid import UUID

import yaml  # type: ignore[import]
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.asset import Asset, AssetType
from app.models.db.user import User

router = APIRouter(prefix="/cloud", tags=["Cloud Discovery"])

_CLOUDLIST_TIMEOUT = 120  # seconds


def _build_cloudlist_config(provider: str, credentials: dict) -> dict:
    """Build a cloudlist-compatible YAML config from provider credentials."""
    if provider == "aws":
        return {
            "aws": [
                {
                    "id": credentials.get("access_key_id", ""),
                    "secret": credentials.get("secret_access_key", ""),
                    "token": credentials.get("session_token", ""),
                }
            ]
        }
    elif provider == "gcp":
        return {
            "gcp": [
                {
                    "service_account_path": credentials.get("service_account_path", ""),
                }
            ]
        }
    elif provider == "azure":
        return {
            "azure": [
                {
                    "client_id": credentials.get("client_id", ""),
                    "client_secret": credentials.get("client_secret", ""),
                    "tenant_id": credentials.get("tenant_id", ""),
                    "subscription_id": credentials.get("subscription_id", ""),
                }
            ]
        }
    return {}


@router.post("/discover", summary="Discover cloud assets via cloudlist")
async def discover_cloud_assets(
    body: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Enumerate cloud assets using cloudlist (projectdiscovery/cloudlist).
    Falls back with an install hint if cloudlist is not available.

    Body:
        provider  — "aws" | "gcp" | "azure"
        credentials — provider-specific credential fields
    """
    provider = body.get("provider", "aws")
    credentials: dict = body.get("credentials", {})

    valid_providers = {"aws", "gcp", "azure"}
    if provider not in valid_providers:
        raise HTTPException(status_code=400, detail=f"provider must be one of: {', '.join(valid_providers)}")

    cloudlist_bin = shutil.which("cloudlist")
    if not cloudlist_bin:
        return {
            "discovered": 0,
            "assets": [],
            "provider": provider,
            "message": (
                "cloudlist not installed. "
                "Install with: go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
            ),
        }

    config = _build_cloudlist_config(provider, credentials)

    # Write temporary credentials config file
    config_fd, config_path = tempfile.mkstemp(suffix=".yaml")
    try:
        with os.fdopen(config_fd, "w") as f:
            yaml.dump(config, f)

        proc = await asyncio.create_subprocess_exec(
            cloudlist_bin,
            "-config", config_path,
            "-json",
            "-provider", provider,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_CLOUDLIST_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            raise HTTPException(status_code=408, detail="Cloud discovery timed out after 120 seconds")

        assets = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                value = (
                    item.get("public_ip")
                    or item.get("hostname")
                    or item.get("name")
                    or "unknown"
                )
                assets.append({
                    "value": value,
                    "asset_type": "cloud",
                    "provider": provider,
                    "resource_type": item.get("type", "unknown"),
                    "metadata": item,
                })
            except Exception:
                continue

        return {
            "discovered": len(assets),
            "assets": assets[:100],
            "provider": provider,
        }
    finally:
        try:
            os.unlink(config_path)
        except OSError:
            pass


@router.get("/assets", summary="List cloud assets for this org")
async def list_cloud_assets(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return all cloud-type assets belonging to the current org (up to 500)."""
    result = await db.execute(
        select(Asset)
        .where(Asset.org_id == org_id, Asset.asset_type == AssetType.CLOUD)
        .limit(500)
    )
    assets = result.scalars().all()
    return {
        "items": [
            {
                "id": str(a.id),
                "value": a.value,
                "tags": a.tags,
                "is_active": a.is_active,
                "risk_score": a.risk_score,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                "metadata": a.metadata_,
            }
            for a in assets
        ],
        "total": len(assets),
    }
