"""
Container & Kubernetes Security Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scans for container and Kubernetes misconfigurations:
  - Exposed Kubernetes API endpoints (unauthenticated access)
  - Docker Registry enumeration (open catalog, tag listing)
  - Container image analysis (Docker Hub manifest, config checks)
  - Common K8s component port exposure (etcd, kubelet, kube-proxy)
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, AsyncGenerator
from urllib.parse import urlparse
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User
from app.services.enrichment_service import batch_enrich_cves
from app.api.v1.dashboard import invalidate_dashboard_cache
from app.services.finding_ingest import ingest_findings

# ── Filesystem history ────────────────────────────────────────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "container_scanner" / org_id
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


# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/container", tags=["Container Scanner"])

# ── Check definitions ─────────────────────────────────────────────────────────

K8S_ENDPOINTS = [
    "/api",
    "/api/v1/pods",
    "/api/v1/secrets",
    "/api/v1/namespaces",
    "/apis/apps/v1/deployments",
    "/version",
    "/metrics",
    "/healthz",
    "/readyz",
]

REGISTRY_ENDPOINTS = [
    "/v2/",
    "/v2/_catalog",
    "/v1/search",
]

K8S_COMPONENT_CHECKS = [
    {"id": "K001", "name": "Kubernetes Dashboard Exposed", "severity": "critical",
     "path": "/api/v1/namespaces/kubernetes-dashboard/services/kubernetes-dashboard"},
    {"id": "K002", "name": "etcd Exposed on Port 2379", "severity": "critical",
     "port": 2379, "path": "/version"},
    {"id": "K003", "name": "Kubelet API Exposed on 10250", "severity": "critical",
     "port": 10250, "path": "/pods"},
    {"id": "K004", "name": "Kubelet Read-Only Exposed on 10255", "severity": "high",
     "port": 10255, "path": "/pods"},
    {"id": "K005", "name": "kube-proxy Exposed on 10256", "severity": "medium",
     "port": 10256, "path": "/healthz"},
    {"id": "K006", "name": "cAdvisor Exposed on 4194", "severity": "medium",
     "port": 4194, "path": "/metrics"},
]

CHECK_CATEGORIES = {
    "kubernetes_api": {
        "name": "Kubernetes API Exposure",
        "description": "Tests K8s API server endpoints for unauthenticated access",
        "checks": ["Unauthenticated /api", "Pod listing", "Secret listing", "Namespace listing",
                   "Deployment listing", "Version disclosure", "Metrics exposure", "Health endpoints"],
    },
    "k8s_components": {
        "name": "K8s Component Port Exposure",
        "description": "Checks for exposed etcd, kubelet, kube-proxy, cAdvisor ports",
        "checks": ["etcd (2379)", "kubelet (10250)", "kubelet read-only (10255)",
                   "kube-proxy (10256)", "cAdvisor (4194)", "Dashboard exposure"],
    },
    "registry": {
        "name": "Docker Registry Exposure",
        "description": "Tests for open Docker registry catalog and unauthenticated image listing",
        "checks": ["Registry v2 API", "Catalog listing", "Image tag enumeration"],
    },
    "image": {
        "name": "Container Image Analysis",
        "description": "Analyzes container image configuration for security issues",
        "checks": ["Root user check", "HEALTHCHECK presence", "Sensitive port exposure",
                   "Environment variable secrets", "Base image vulnerability check"],
    },
}

SENSITIVE_ENV_PATTERNS = [
    "password", "passwd", "secret", "token", "key", "api_key", "apikey",
    "auth", "credential", "private", "access_key", "aws_secret",
]

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 23: "Telnet", 5900: "VNC", 1433: "MSSQL", 3306: "MySQL"}

KNOWN_VULNERABLE_TAGS = {
    "latest": "info",   # using 'latest' is bad practice
    "master": "info",
    "dev": "low",
    "test": "low",
}

# ── SSE helper ────────────────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


# ── Pydantic model ────────────────────────────────────────────────────────────

class ContainerScanRequest(BaseModel):
    scan_type: str  # "image", "kubernetes_api", "exposed_registry"
    image: str | None = None
    k8s_api_url: str | None = None
    k8s_token: str | None = None
    registry_url: str | None = None
    check_cve: bool = True
    check_config: bool = True
    check_secrets: bool = True


# ── Finding-quality adapter (shared across all 3 scan types — same shape) ────

_CATEGORY_CONFIDENCE = {
    "Kubernetes API": "certain",
    "K8s Component Exposure": "certain",
    "Registry Exposure": "certain",
    "Registry Misconfiguration": "certain",
    "CVE": "high",
    "Configuration": "high",
    "Image Tag Policy": "high",
    "Secret in Image": "medium",
}


async def _adapt_container_findings(findings: list[dict]) -> list[dict]:
    """Normalize container_scanner.py findings (same shape across all 3 scan
    types: kubernetes_api, exposed_registry, image) for finding_ingest, with
    CVSS/EPSS/KEV enrichment for Trivy-sourced CVE findings."""
    cve_ids = list({f["cve_id"] for f in findings if f.get("cve_id")})
    enrichment = await batch_enrich_cves(cve_ids) if cve_ids else {}

    adapted = []
    for f in findings:
        cve_id = f.get("cve_id")
        enrich = enrichment.get((cve_id or "").upper(), {})
        adapted.append({
            "title": f.get("title", f.get("check", "Container finding")),
            "description": f.get("detail", ""),
            "severity": f.get("severity", "medium"),
            "category": f"container-{f.get('category', 'unknown')}",
            "affected_asset": f.get("resource", ""),
            "evidence": {"check": f.get("check"), "evidence": f.get("evidence")},
            "remediation": f.get("remediation", ""),
            "cve": [cve_id] if cve_id else [],
            "confidence": _CATEGORY_CONFIDENCE.get(f.get("category", ""), "medium"),
            "cvss_score": enrich.get("cvss_v4_score"),
            "epss_score": enrich.get("epss_score"),
            "kev_status": enrich.get("is_kev", False),
        })
    return adapted


# ── Core scan generators ──────────────────────────────────────────────────────

async def _scan_kubernetes_api(
    k8s_api_url: str,
    k8s_token: str | None,
    scan_id: str,
    started_at: str,
    org_id: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    base = k8s_api_url.rstrip("/")
    findings: list[dict] = []

    headers: dict[str, str] = {"User-Agent": "AttackTrace/1.0"}
    if k8s_token:
        headers["Authorization"] = f"Bearer {k8s_token}"

    yield _sse("start", {
        "scan_id": scan_id,
        "scan_type": "kubernetes_api",
        "target": base,
        "total_checks": len(K8S_ENDPOINTS) + len(K8S_COMPONENT_CHECKS),
    })

    # Phase 1: Test K8s API endpoints for unauthenticated access
    parsed = urlparse(base)
    host_base = f"{parsed.scheme}://{parsed.hostname}"

    async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
        for i, endpoint in enumerate(K8S_ENDPOINTS):
            url = f"{base}{endpoint}"
            yield _sse("progress", {
                "phase": "k8s_api",
                "checked": i + 1,
                "total": len(K8S_ENDPOINTS),
                "current": endpoint,
            })
            try:
                # Test without auth first if no token provided, or always test
                test_headers = {"User-Agent": "AttackTrace/1.0"}
                resp = await client.get(url, headers=test_headers)

                if resp.status_code == 200:
                    severity = "critical"
                    detail = f"Kubernetes API endpoint {endpoint} is accessible without authentication"

                    body_preview = ""
                    try:
                        body_data = resp.json()
                        body_preview = json.dumps(body_data)[:300]

                        # Extra check: secrets endpoint returning actual data
                        if endpoint == "/api/v1/secrets" and "items" in body_data:
                            secret_count = len(body_data.get("items", []))
                            detail = f"Kubernetes Secrets exposed without authentication — {secret_count} secret(s) found"
                            severity = "critical"

                        if endpoint == "/api/v1/pods" and "items" in body_data:
                            pod_count = len(body_data.get("items", []))
                            detail = f"Kubernetes Pod listing accessible without authentication — {pod_count} pod(s) found"

                        if endpoint == "/version":
                            git_ver = body_data.get("gitVersion", "")
                            detail = f"Kubernetes version info disclosed without authentication — {git_ver}"
                            severity = "medium"

                        if endpoint == "/metrics":
                            detail = "Kubernetes Prometheus metrics exposed without authentication"
                            severity = "high"

                    except Exception:
                        body_preview = resp.text[:300]

                    finding = {
                        "id": str(_uuid_mod.uuid4()),
                        "severity": severity,
                        "category": "Kubernetes API",
                        "check": f"Unauthenticated {endpoint}",
                        "title": f"K8s API {endpoint} Accessible Without Auth",
                        "detail": detail,
                        "resource": url,
                        "evidence": body_preview[:200],
                        "remediation": f"Restrict access to {endpoint} using RBAC and network policies. Enable authentication on the API server.",
                    }
                    findings.append(finding)
                    yield _sse("finding", finding)

                elif resp.status_code == 401:
                    yield _sse("info", {"message": f"{endpoint} — 401 Unauthorized (protected)", "endpoint": endpoint})
                elif resp.status_code == 403:
                    yield _sse("info", {"message": f"{endpoint} — 403 Forbidden (RBAC enforced)", "endpoint": endpoint})

            except httpx.ConnectError:
                yield _sse("info", {"message": f"{endpoint} — connection refused", "endpoint": endpoint})
            except Exception as exc:
                yield _sse("info", {"message": f"{endpoint} — error: {str(exc)[:80]}", "endpoint": endpoint})

        # Phase 2: Check K8s component ports
        if parsed.hostname:
            for check in K8S_COMPONENT_CHECKS:
                if "port" in check:
                    port = check["port"]
                    path = check.get("path", "/")
                    component_url = f"http://{parsed.hostname}:{port}{path}"
                    yield _sse("progress", {
                        "phase": "component_ports",
                        "current": check["name"],
                    })
                    try:
                        resp = await client.get(component_url, headers={"User-Agent": "AttackTrace/1.0"})
                        if resp.status_code in (200, 301, 302):
                            finding = {
                                "id": str(_uuid_mod.uuid4()),
                                "severity": check["severity"],
                                "category": "K8s Component Exposure",
                                "check": check["id"],
                                "title": check["name"],
                                "detail": f"{check['name']} is accessible from the network without authentication at port {port}",
                                "resource": component_url,
                                "evidence": resp.text[:200],
                                "remediation": f"Restrict port {port} using firewall rules and bind to localhost only.",
                            }
                            findings.append(finding)
                            yield _sse("finding", finding)
                    except Exception:
                        pass

                elif "path" in check and check["id"] == "K001":
                    # Dashboard check via main API
                    dashboard_url = f"{base}{check['path']}"
                    try:
                        resp = await client.get(dashboard_url, headers={"User-Agent": "AttackTrace/1.0"})
                        if resp.status_code == 200:
                            finding = {
                                "id": str(_uuid_mod.uuid4()),
                                "severity": check["severity"],
                                "category": "K8s Component Exposure",
                                "check": check["id"],
                                "title": check["name"],
                                "detail": "Kubernetes Dashboard service is exposed and accessible via the API server",
                                "resource": dashboard_url,
                                "evidence": resp.text[:200],
                                "remediation": "Remove the Kubernetes Dashboard or restrict access with authentication and network policies.",
                            }
                            findings.append(finding)
                            yield _sse("finding", finding)
                    except Exception:
                        pass

    summary = _build_summary(findings, scan_type="kubernetes_api", target=base)
    record = {
        "id": scan_id,
        "scan_type": "kubernetes_api",
        "target": base,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "findings": findings,
        "summary": summary,
    }
    if org_id:
        _save_scan_result(org_id, record)
        try:
            adapted = await _adapt_container_findings(findings)
            await ingest_findings(db, org_id, source="container_scanner", source_scan_id=scan_id, findings=adapted)
            await db.commit()
            await invalidate_dashboard_cache(org_id)
        except Exception:
            await db.rollback()

    yield _sse("complete", record)


async def _scan_registry(
    registry_url: str,
    scan_id: str,
    started_at: str,
    org_id: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    base = registry_url.rstrip("/")
    findings: list[dict] = []

    yield _sse("start", {
        "scan_id": scan_id,
        "scan_type": "exposed_registry",
        "target": base,
        "total_checks": len(REGISTRY_ENDPOINTS),
    })

    repositories: list[str] = []

    async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as client:
        for i, endpoint in enumerate(REGISTRY_ENDPOINTS):
            url = f"{base}{endpoint}"
            yield _sse("progress", {
                "phase": "registry_probe",
                "checked": i + 1,
                "total": len(REGISTRY_ENDPOINTS),
                "current": endpoint,
            })
            try:
                resp = await client.get(url, headers={"User-Agent": "AttackTrace/1.0"})

                if resp.status_code == 200:
                    if endpoint == "/v2/_catalog":
                        try:
                            data = resp.json()
                            repos = data.get("repositories", [])
                            repositories = repos
                            finding = {
                                "id": str(_uuid_mod.uuid4()),
                                "severity": "critical",
                                "category": "Registry Exposure",
                                "check": "Open Catalog",
                                "title": "Docker Registry Catalog Exposed Without Authentication",
                                "detail": f"Registry catalog lists {len(repos)} repositories without requiring authentication: {', '.join(repos[:10])}",
                                "resource": url,
                                "evidence": json.dumps(data)[:300],
                                "remediation": "Enable authentication on the Docker registry. Use basic auth or token-based auth with TLS.",
                            }
                            findings.append(finding)
                            yield _sse("finding", finding)
                        except Exception:
                            pass

                    elif endpoint == "/v2/":
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": "medium",
                            "category": "Registry Exposure",
                            "check": "Registry API v2",
                            "title": "Docker Registry v2 API Accessible",
                            "detail": "Registry v2 API responds without authentication challenge",
                            "resource": url,
                            "evidence": resp.text[:200],
                            "remediation": "Configure authentication on the registry. The /v2/ endpoint should return a 401 with WWW-Authenticate header.",
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)

                    elif endpoint == "/v1/search":
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": "high",
                            "category": "Registry Exposure",
                            "check": "V1 Search API",
                            "title": "Docker Registry v1 Search Exposed",
                            "detail": "Legacy Docker Registry v1 search API is accessible without authentication",
                            "resource": url,
                            "evidence": resp.text[:200],
                            "remediation": "Disable legacy v1 API support and migrate to v2 with authentication.",
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)

                elif resp.status_code == 401:
                    # Check if WWW-Authenticate is missing (misconfigured)
                    if endpoint == "/v2/" and "www-authenticate" not in {k.lower() for k in resp.headers}:
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": "low",
                            "category": "Registry Misconfiguration",
                            "check": "Missing WWW-Authenticate",
                            "title": "Registry Returns 401 Without WWW-Authenticate Header",
                            "detail": "The registry requires auth but does not advertise auth mechanism via WWW-Authenticate header",
                            "resource": url,
                            "evidence": dict(resp.headers).__str__()[:200],
                            "remediation": "Configure proper WWW-Authenticate header so clients know how to authenticate.",
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)
                    else:
                        yield _sse("info", {"message": f"{endpoint} — 401 protected (expected)", "endpoint": endpoint})

            except httpx.ConnectError:
                yield _sse("info", {"message": f"Cannot connect to registry at {url}", "endpoint": endpoint})
            except Exception as exc:
                yield _sse("info", {"message": f"{endpoint} error: {str(exc)[:80]}", "endpoint": endpoint})

        # Phase 2: Enumerate tags for discovered repositories
        if repositories:
            yield _sse("progress", {"phase": "tag_enumeration", "total_repos": len(repositories)})
            for repo in repositories[:20]:  # cap at 20 repos
                tags_url = f"{base}/v2/{repo}/tags/list"
                try:
                    resp = await client.get(tags_url, headers={"User-Agent": "AttackTrace/1.0"})
                    if resp.status_code == 200:
                        data = resp.json()
                        tags = data.get("tags", [])
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": "high",
                            "category": "Registry Exposure",
                            "check": "Tag Enumeration",
                            "title": f"Image Tags for '{repo}' Enumerable Without Auth",
                            "detail": f"Repository '{repo}' has {len(tags)} tags accessible without authentication: {', '.join((tags or [])[:10])}",
                            "resource": tags_url,
                            "evidence": json.dumps(data)[:300],
                            "remediation": "Enable registry authentication to prevent unauthorized image enumeration.",
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)
                except Exception:
                    pass

    summary = _build_summary(findings, scan_type="exposed_registry", target=base)
    record = {
        "id": scan_id,
        "scan_type": "exposed_registry",
        "target": base,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "findings": findings,
        "summary": summary,
    }
    if org_id:
        _save_scan_result(org_id, record)
        try:
            adapted = await _adapt_container_findings(findings)
            await ingest_findings(db, org_id, source="container_scanner", source_scan_id=scan_id, findings=adapted)
            await db.commit()
            await invalidate_dashboard_cache(org_id)
        except Exception:
            await db.rollback()

    yield _sse("complete", record)


async def _scan_image(
    image: str,
    check_cve: bool,
    check_config: bool,
    check_secrets: bool,
    scan_id: str,
    started_at: str,
    org_id: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    findings: list[dict] = []

    yield _sse("start", {
        "scan_id": scan_id,
        "scan_type": "image",
        "target": image,
    })

    # Normalise image reference
    image_clean = image.strip()
    if ":" in image_clean:
        image_name, tag = image_clean.rsplit(":", 1)
    else:
        image_name, tag = image_clean, "latest"

    # Check for tool availability
    has_trivy = shutil.which("trivy") is not None
    has_docker = shutil.which("docker") is not None

    yield _sse("progress", {
        "phase": "tool_detection",
        "trivy_available": has_trivy,
        "docker_available": has_docker,
        "method": "trivy" if has_trivy else ("docker" if has_docker else "dockerhub_api"),
    })

    if has_trivy:
        # Use trivy for full vulnerability scan
        import subprocess
        yield _sse("progress", {"phase": "trivy_scan", "message": f"Running trivy on {image_clean}"})
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "image", "--format", "json", "--quiet", image_clean,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode == 0 and stdout:
                trivy_data = json.loads(stdout)
                results = trivy_data.get("Results", [])
                for result in results:
                    vulns = result.get("Vulnerabilities") or []
                    for v in vulns:
                        sev = v.get("Severity", "UNKNOWN").lower()
                        if sev == "unknown":
                            sev = "info"
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": sev,
                            "category": "CVE",
                            "check": "Trivy CVE Scan",
                            "title": f"{v.get('VulnerabilityID', 'CVE')} in {v.get('PkgName', 'package')}",
                            "detail": v.get("Description", "No description available")[:300],
                            "resource": image_clean,
                            "evidence": f"Package: {v.get('PkgName')} {v.get('InstalledVersion')} → Fixed in: {v.get('FixedVersion', 'N/A')}",
                            "remediation": f"Update {v.get('PkgName')} to version {v.get('FixedVersion', 'latest')} or rebuild with a patched base image.",
                            "cve_id": v.get("VulnerabilityID"),
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)
                yield _sse("progress", {"phase": "trivy_complete", "total_vulns": len(findings)})
        except asyncio.TimeoutError:
            yield _sse("info", {"message": "Trivy scan timed out after 120s"})
        except Exception as exc:
            yield _sse("info", {"message": f"Trivy error: {str(exc)[:100]}"})

    elif has_docker:
        # Use docker inspect for config analysis
        import subprocess
        yield _sse("progress", {"phase": "docker_pull", "message": f"Pulling {image_clean}"})
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "pull", image_clean,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

            # docker inspect
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", image_clean,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            if stdout:
                inspect_data = json.loads(stdout)
                config = inspect_data[0].get("Config", {}) if inspect_data else {}

                # Check running as root
                if check_config:
                    user = config.get("User", "")
                    if not user or user in ("", "0", "root"):
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": "high",
                            "category": "Configuration",
                            "check": "Root User",
                            "title": "Container Runs as Root",
                            "detail": f"Image '{image_clean}' is configured to run as root (User: '{user}'). This increases blast radius if the container is compromised.",
                            "resource": image_clean,
                            "evidence": f"Config.User = '{user}'",
                            "remediation": "Add a USER directive in Dockerfile to run as a non-root user (e.g., USER 1001).",
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)

                    # HEALTHCHECK
                    healthcheck = config.get("Healthcheck")
                    if not healthcheck:
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": "low",
                            "category": "Configuration",
                            "check": "HEALTHCHECK",
                            "title": "No HEALTHCHECK Defined",
                            "detail": f"Image '{image_clean}' has no HEALTHCHECK instruction. Kubernetes/Docker cannot detect unhealthy containers.",
                            "resource": image_clean,
                            "evidence": "Config.Healthcheck = null",
                            "remediation": "Add a HEALTHCHECK instruction to the Dockerfile.",
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)

                    # Exposed sensitive ports
                    exposed_ports = config.get("ExposedPorts", {})
                    for port_proto in exposed_ports:
                        port_num = int(port_proto.split("/")[0])
                        if port_num in SENSITIVE_PORTS:
                            finding = {
                                "id": str(_uuid_mod.uuid4()),
                                "severity": "medium",
                                "category": "Configuration",
                                "check": "Sensitive Port",
                                "title": f"Sensitive Port {port_num} ({SENSITIVE_PORTS[port_num]}) Exposed",
                                "detail": f"Image '{image_clean}' exposes port {port_num} ({SENSITIVE_PORTS[port_num]}), which is typically a sensitive administrative service.",
                                "resource": image_clean,
                                "evidence": f"ExposedPorts: {port_proto}",
                                "remediation": f"Remove the EXPOSE {port_num} from Dockerfile unless absolutely necessary. Never expose administrative ports in production images.",
                            }
                            findings.append(finding)
                            yield _sse("finding", finding)

                # Check environment variables for secrets
                if check_secrets:
                    env_vars = config.get("Env", [])
                    for env_var in env_vars:
                        name_part = env_var.split("=")[0].lower() if "=" in env_var else env_var.lower()
                        if any(pat in name_part for pat in SENSITIVE_ENV_PATTERNS):
                            value_part = env_var.split("=", 1)[1] if "=" in env_var else ""
                            # Only flag if value is non-empty and not a placeholder
                            if value_part and value_part not in ("", "changeme", "placeholder", "your_secret_here"):
                                finding = {
                                    "id": str(_uuid_mod.uuid4()),
                                    "severity": "critical",
                                    "category": "Secret in Image",
                                    "check": "Environment Secret",
                                    "title": f"Potential Secret in Environment Variable: {env_var.split('=')[0]}",
                                    "detail": f"Environment variable '{env_var.split('=')[0]}' appears to contain a sensitive value baked into the image",
                                    "resource": image_clean,
                                    "evidence": f"{env_var.split('=')[0]}=***REDACTED***",
                                    "remediation": "Never bake secrets into Docker images. Use Docker secrets, environment injection at runtime, or a secrets manager.",
                                }
                                findings.append(finding)
                                yield _sse("finding", finding)

        except asyncio.TimeoutError:
            yield _sse("info", {"message": "Docker pull/inspect timed out"})
        except Exception as exc:
            yield _sse("info", {"message": f"Docker error: {str(exc)[:100]}"})

    else:
        # Pure Python fallback: Docker Hub API
        yield _sse("progress", {"phase": "dockerhub_api", "message": "Using Docker Hub API (no local tools found)"})

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            # Determine if it's an official/library image or user image
            if "/" not in image_name:
                hub_name = f"library/{image_name}"
            else:
                hub_name = image_name

            # Tag-based checks
            if check_config:
                tag_lower = tag.lower()
                if tag_lower in KNOWN_VULNERABLE_TAGS:
                    finding = {
                        "id": str(_uuid_mod.uuid4()),
                        "severity": KNOWN_VULNERABLE_TAGS[tag_lower],
                        "category": "Image Tag Policy",
                        "check": "Mutable Tag",
                        "title": f"Using Mutable Image Tag '{tag}'",
                        "detail": f"The image '{image_clean}' uses the '{tag}' tag which is mutable and can change unexpectedly, leading to non-reproducible deployments.",
                        "resource": image_clean,
                        "evidence": f"Image tag: {tag}",
                        "remediation": "Pin to a specific immutable digest (e.g., nginx@sha256:abc123) or a versioned tag (e.g., nginx:1.25.3).",
                    }
                    findings.append(finding)
                    yield _sse("finding", finding)

            # Docker Hub API: check if image exists and get metadata
            try:
                hub_url = f"https://hub.docker.com/v2/repositories/{hub_name}/"
                resp = await client.get(hub_url)
                if resp.status_code == 200:
                    repo_data = resp.json()
                    pull_count = repo_data.get("pull_count", 0)
                    description = repo_data.get("description", "")
                    is_official = repo_data.get("is_official", False)

                    yield _sse("info", {
                        "message": f"Image found on Docker Hub: {image_name} ({pull_count:,} pulls)",
                        "is_official": is_official,
                        "description": description[:100],
                    })

                elif resp.status_code == 404:
                    yield _sse("info", {"message": f"Image '{image_name}' not found on Docker Hub (may be a private registry)"})

            except Exception:
                pass

            # Try to fetch manifest for layer analysis
            try:
                auth_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{hub_name}:pull"
                auth_resp = await client.get(auth_url)
                if auth_resp.status_code == 200:
                    token = auth_resp.json().get("token", "")
                    manifest_url = f"https://registry-1.docker.io/v2/{hub_name}/manifests/{tag}"
                    manifest_resp = await client.get(
                        manifest_url,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.docker.distribution.manifest.v2+json",
                        }
                    )
                    if manifest_resp.status_code == 200:
                        manifest_data = manifest_resp.json()
                        layers = manifest_data.get("layers", [])
                        total_size = sum(l.get("size", 0) for l in layers)
                        yield _sse("info", {
                            "message": f"Image manifest retrieved: {len(layers)} layers, {total_size // 1024 // 1024}MB total",
                            "layers": len(layers),
                        })
                    elif manifest_resp.status_code == 404:
                        finding = {
                            "id": str(_uuid_mod.uuid4()),
                            "severity": "info",
                            "category": "Image",
                            "check": "Image Existence",
                            "title": f"Image Tag '{tag}' Not Found",
                            "detail": f"The tag '{tag}' does not exist for image '{image_name}'. This may cause deployment failures.",
                            "resource": image_clean,
                            "evidence": f"HTTP 404 from registry for {hub_name}:{tag}",
                            "remediation": "Verify the correct image tag exists in the registry.",
                        }
                        findings.append(finding)
                        yield _sse("finding", finding)
            except Exception:
                pass

    summary = _build_summary(findings, scan_type="image", target=image_clean)
    record = {
        "id": scan_id,
        "scan_type": "image",
        "target": image_clean,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "findings": findings,
        "summary": summary,
    }
    if org_id:
        _save_scan_result(org_id, record)
        try:
            adapted = await _adapt_container_findings(findings)
            await ingest_findings(db, org_id, source="container_scanner", source_scan_id=scan_id, findings=adapted)
            await db.commit()
            await invalidate_dashboard_cache(org_id)
        except Exception:
            await db.rollback()

    yield _sse("complete", record)


def _build_summary(findings: list[dict], scan_type: str, target: str) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return {
        "scan_type": scan_type,
        "target": target,
        "total_findings": len(findings),
        **counts,
    }


# ── Route dispatcher ──────────────────────────────────────────────────────────

async def _run_container_scan(req: ContainerScanRequest, org_id: str, db: AsyncSession) -> AsyncGenerator[str, None]:
    scan_id = str(_uuid_mod.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    if req.scan_type == "kubernetes_api":
        if not req.k8s_api_url:
            yield _sse("error", {"message": "k8s_api_url is required for kubernetes_api scan type"})
            return
        async for event in _scan_kubernetes_api(
            req.k8s_api_url, req.k8s_token, scan_id, started_at, org_id, db
        ):
            yield event

    elif req.scan_type == "exposed_registry":
        if not req.registry_url:
            yield _sse("error", {"message": "registry_url is required for exposed_registry scan type"})
            return
        async for event in _scan_registry(req.registry_url, scan_id, started_at, org_id, db):
            yield event

    elif req.scan_type == "image":
        if not req.image:
            yield _sse("error", {"message": "image is required for image scan type"})
            return
        async for event in _scan_image(
            req.image, req.check_cve, req.check_config, req.check_secrets,
            scan_id, started_at, org_id, db
        ):
            yield event

    else:
        yield _sse("error", {"message": f"Unknown scan_type: {req.scan_type}"})


# ── HTTP endpoints ────────────────────────────────────────────────────────────

OrgID = Annotated[str, Depends(get_current_org_id)]
CurrentUser = Annotated[User, Depends(get_current_user)]


@router.get("/history")
async def get_history(org_id: OrgID, _: CurrentUser) -> list[dict]:
    """Return scan history for the current org (newest first, max 50)."""
    return _load_history(org_id)


@router.get("/history/{scan_id}")
async def get_scan(scan_id: str, org_id: OrgID, _: CurrentUser) -> dict:
    """Return a single scan record by ID."""
    record = _load_scan(org_id, scan_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str, org_id: OrgID, _: CurrentUser) -> None:
    """Delete a scan record by ID."""
    if not _delete_scan(org_id, scan_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")


@router.get("/checks")
async def get_checks(_: CurrentUser) -> dict:
    """Return available check categories and their descriptions."""
    return {
        "scan_types": [
            {"id": "kubernetes_api", "name": "Kubernetes API Check", "description": "Tests K8s API server for unauthenticated access"},
            {"id": "exposed_registry", "name": "Docker Registry Check", "description": "Enumerates open Docker registries"},
            {"id": "image", "name": "Container Image Scan", "description": "Analyzes a container image for security issues"},
        ],
        "check_categories": CHECK_CATEGORIES,
        "k8s_component_checks": K8S_COMPONENT_CHECKS,
        "k8s_endpoints": K8S_ENDPOINTS,
        "registry_endpoints": REGISTRY_ENDPOINTS,
    }


@router.post("/scan")
async def run_scan(
    req: ContainerScanRequest, org_id: OrgID, _: CurrentUser, db: AsyncSession = Depends(get_db)
) -> StreamingResponse:
    """Start a container/Kubernetes security scan. Returns Server-Sent Events."""
    return StreamingResponse(
        _run_container_scan(req, org_id, db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
