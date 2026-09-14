"""
Cloud Asset Discovery API — uses cloudlist (projectdiscovery) to enumerate
cloud resources across AWS, GCP, and Azure.
"""

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
import uuid as _uuid_mod
from pathlib import Path
from typing import Annotated
from uuid import UUID

import yaml  # type: ignore[import]
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.core.finding_confidence import grade_confidence
from app.core.remediation import get_remediation
from app.models.db.asset import Asset, AssetType
from app.models.db.user import User
from app.services.asset_upsert import upsert_asset_async
from app.services.finding_ingest import ingest_findings

router = APIRouter(prefix="/cloud", tags=["Cloud Discovery"])

_CLOUDLIST_TIMEOUT = 120  # seconds

# ── Filesystem history (org-scoped, path-traversal-safe) ─────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "cloud_discovery" / org_id
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
    path = _safe_history_path(org_id, scan_id)
    if path.exists():
        path.unlink()
        return True
    return False


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


def _cloud_resource_risk(resource_type: str, public_ip: str, hostname: str) -> tuple[str, str, str] | None:
    """Classify a single discovered cloud resource for security relevance.

    cloudlist is a pure asset-enumeration tool — it queries each provider's
    API for resources the supplied credentials can see. It does not itself
    assess misconfigurations (bucket ACLs, IAM policies, encryption-at-rest,
    security-group rules). The only security-relevant signal actually present
    in its output is whether a resource is directly reachable from the public
    internet, and whether its resource type is one that normally should not
    be (storage/database/cache/cluster-management/admin interfaces) versus
    resource types that are intentionally public (DNS records, CDN
    distributions, load balancers). Returns (title, severity, category), or
    None if this is pure inventory with no exposure signal worth a Finding —
    those stay visible only as Assets.
    """
    if not (public_ip or hostname):
        return None

    rt = (resource_type or "").lower()

    # Resource types that are supposed to be internet-facing — not a finding.
    if any(k in rt for k in ("dns", "cdn", "loadbalancer", "load-balancer", "elb", "alb", "waf", "cloudfront")):
        return None

    if any(k in rt for k in ("bucket", "storage", "s3", "blob", "container")):
        return ("Publicly reachable cloud storage resource", "critical", "cloud-storage-exposure")
    if any(k in rt for k in ("database", "rds", "sql", "mongo", "redis", "cache", "elasticsearch", "cosmosdb", "dynamodb")):
        return ("Publicly reachable cloud database/cache resource", "critical", "cloud-data-exposure")
    if any(k in rt for k in ("kubernetes", "k8s", "cluster", "eks", "gke", "aks")):
        return ("Publicly reachable cluster management endpoint", "high", "cloud-cluster-exposure")
    if any(k in rt for k in ("admin", "management", "console", "bastion")):
        return ("Publicly reachable cloud admin/management interface", "high", "cloud-admin-exposure")
    if any(k in rt for k in ("instance", "vm", "compute", "server", "function", "lambda", "vmss")):
        return ("Cloud compute resource directly exposed to the internet", "medium", "cloud-compute-exposure")
    return ("Cloud resource directly exposed to the internet", "low", "cloud-exposure")


def _adapt_cloud_findings(assets: list[dict], provider: str) -> list[dict]:
    """Normalize cloud.py's discovered assets for finding_ingest.

    Confidence is graded "api-confirmed" (-> certain): the exposure fact
    (public IP/hostname) is read directly from the cloud provider's own API
    response, not inferred or guessed.
    """
    adapted = []
    for a in assets:
        meta = a.get("metadata") or {}
        public_ip = str(meta.get("public_ip") or meta.get("public_ipv4") or "")
        hostname = str(meta.get("hostname") or "")
        resource_type = str(a.get("resource_type") or "unknown")

        classification = _cloud_resource_risk(resource_type, public_ip, hostname)
        if classification is None:
            continue
        title, severity, category = classification
        value = str(a.get("value") or "unknown")

        reachable_via = f"public IP {public_ip}" if public_ip else f"hostname {hostname}"
        adapted.append({
            "title": f"{title} ({provider}: {resource_type})",
            "description": (
                f"Cloud asset discovery ({provider}) found a '{resource_type}' resource "
                f"({value}) directly reachable from the public internet via {reachable_via}. "
                "Confirm this exposure is intentional and reviewed for the access it grants."
            ),
            "severity": severity,
            "category": category,
            "affected_asset": value,
            "evidence": {
                "provider": provider,
                "resource_type": resource_type,
                "public_ip": public_ip or None,
                "hostname": hostname or None,
            },
            "remediation": get_remediation(category=category, title=title),
            "confidence": grade_confidence("api-confirmed"),
        })
    return adapted


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

        record = {
            "id": str(_uuid_mod.uuid4()),
            "provider": provider,
            "discovered": len(assets),
            "assets": assets[:100],
            "created_at": time.time(),
        }
        _save_scan_result(str(org_id), record)

        try:
            for a in assets:
                await upsert_asset_async(
                    db,
                    org_id,
                    AssetType.CLOUD,
                    str(a.get("value") or "unknown"),
                    {
                        "provider": a.get("provider"),
                        "resource_type": a.get("resource_type"),
                        "cloudlist": a.get("metadata"),
                    },
                )
            adapted = _adapt_cloud_findings(assets, provider)
            await ingest_findings(db, org_id, source="cloud", source_scan_id=record["id"], findings=adapted)
            await db.commit()
        except Exception:
            await db.rollback()

        return {
            "id": record["id"],
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


@router.get("/history", summary="List past cloud discovery runs")
async def list_discovery_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    records = _load_history(str(org_id))
    return {
        "items": [
            {
                "id": r.get("id"),
                "provider": r.get("provider"),
                "discovered": r.get("discovered"),
                "created_at": r.get("created_at"),
            }
            for r in records
        ],
        "total": len(records),
    }


@router.get("/history/{scan_id}", summary="Get a past cloud discovery run")
async def get_discovery_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Discovery run not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a past cloud discovery run")
async def delete_discovery_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    deleted = _delete_scan(str(org_id), scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Discovery run not found")
    return {"ok": True, "scan_id": scan_id}
