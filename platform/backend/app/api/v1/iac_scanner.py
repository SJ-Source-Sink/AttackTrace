"""
IaC Security Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Static analysis of Infrastructure-as-Code files.

Supports: Terraform, Kubernetes, Dockerfile, CloudFormation
Runs built-in regex/YAML checks; integrates Checkov when installed.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse

from app.core.config import get_settings as _get_settings
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/iac", tags=["IaC Scanner"])

# ── History helpers (filesystem) ──────────────────────────────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "iac_scanner" / org_id
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


# ── Check rules ───────────────────────────────────────────────────────────────

TERRAFORM_CHECKS = [
    {
        "id": "TF001", "name": "S3 Bucket Public Access", "severity": "critical",
        "pattern": r'resource\s+"aws_s3_bucket"\s+".+?".*?acl\s*=\s*"public',
        "description": "S3 bucket is configured with public ACL",
        "remediation": 'Set acl = "private" and enable block_public_acls',
    },
    {
        "id": "TF002", "name": "Security Group Open Ingress", "severity": "critical",
        "pattern": r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
        "description": "Security group allows ingress from 0.0.0.0/0",
        "remediation": "Restrict cidr_blocks to specific IP ranges",
    },
    {
        "id": "TF003", "name": "RDS Publicly Accessible", "severity": "critical",
        "pattern": r'publicly_accessible\s*=\s*true',
        "description": "RDS instance is publicly accessible",
        "remediation": "Set publicly_accessible = false",
    },
    {
        "id": "TF004", "name": "Hardcoded Credentials", "severity": "critical",
        "pattern": r'(?i)(password|secret|key)\s*=\s*"[^"]{8,}"',
        "description": "Hardcoded credential found in Terraform configuration",
        "remediation": "Use variables or AWS Secrets Manager references",
    },
    {
        "id": "TF005", "name": "Encryption Not Enabled", "severity": "high",
        "pattern": r'encrypted\s*=\s*false',
        "description": "Encryption is explicitly disabled",
        "remediation": "Set encrypted = true",
    },
    {
        "id": "TF006", "name": "Deletion Protection Disabled", "severity": "medium",
        "pattern": r'deletion_protection\s*=\s*false',
        "description": "Deletion protection is disabled on a critical resource",
        "remediation": "Set deletion_protection = true for production resources",
    },
]

KUBERNETES_CHECKS = [
    {
        "id": "K8S001", "name": "Container Runs as Root", "severity": "high",
        "description": "Container configured to run as root user",
        "check": "runAsRoot",
        "remediation": "Set securityContext.runAsNonRoot: true and runAsUser: 1000",
    },
    {
        "id": "K8S002", "name": "Privileged Container", "severity": "critical",
        "description": "Container is running in privileged mode",
        "yaml_path": "spec.containers[*].securityContext.privileged",
        "bad_value": True,
        "check": "privileged",
        "remediation": "Remove privileged: true from securityContext",
    },
    {
        "id": "K8S003", "name": "No Resource Limits", "severity": "medium",
        "description": "Container has no CPU/memory resource limits",
        "check": "noResourceLimits",
        "remediation": "Add resources.limits.cpu and resources.limits.memory",
    },
    {
        "id": "K8S004", "name": "HostPath Volume Mount", "severity": "high",
        "description": "Container mounts hostPath volume — potential container escape",
        "yaml_path": "spec.volumes[*].hostPath",
        "check": "hostPath",
        "remediation": "Avoid hostPath volumes; use PersistentVolumeClaims instead",
    },
    {
        "id": "K8S005", "name": "No Network Policy", "severity": "medium",
        "description": "Namespace has no NetworkPolicy — all pod-to-pod traffic allowed",
        "check": "noNetworkPolicy",
        "remediation": "Create NetworkPolicy resources to restrict traffic",
    },
    {
        "id": "K8S006", "name": "Image Tag is Latest", "severity": "medium",
        "description": "Container image uses :latest tag — non-deterministic deployments",
        "check": "latestTag",
        "remediation": "Pin image to a specific version tag or digest",
    },
    {
        "id": "K8S007", "name": "Secret in Environment Variable", "severity": "high",
        "description": "Sensitive value appears to be hardcoded in env var",
        "check": "secretInEnv",
        "remediation": "Use Kubernetes Secrets or external secret manager",
    },
]

DOCKERFILE_CHECKS = [
    {
        "id": "DF001", "name": "Root User in Dockerfile", "severity": "high",
        "pattern": r'^USER root',
        "description": "Dockerfile sets USER to root",
        "remediation": "Add 'USER nonroot' or create a dedicated user",
    },
    {
        "id": "DF002", "name": "Latest Base Image Tag", "severity": "medium",
        "pattern": r'^FROM .+:latest',
        "description": "Dockerfile uses :latest tag for base image",
        "remediation": "Pin to a specific version: FROM ubuntu:22.04",
    },
    {
        "id": "DF003", "name": "ADD Instead of COPY", "severity": "low",
        "pattern": r'^ADD\s+',
        "description": "ADD instruction used instead of COPY (ADD can fetch URLs)",
        "remediation": "Use COPY for local files; ADD only when decompression needed",
    },
    {
        "id": "DF004", "name": "Hardcoded Secret in ENV", "severity": "critical",
        "pattern": r'^ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=?\s*\S+',
        "description": "Dockerfile hardcodes a secret in ENV instruction",
        "remediation": "Use build args or runtime secrets injection",
    },
    {
        "id": "DF005", "name": "No HEALTHCHECK", "severity": "low",
        "check": "noHealthcheck",
        "description": "No HEALTHCHECK instruction defined",
        "remediation": "Add HEALTHCHECK instruction for container health monitoring",
    },
]

CLOUDFORMATION_CHECKS = [
    {
        "id": "CF001", "name": "S3 Bucket No Versioning", "severity": "medium",
        "pattern": r'"VersioningConfiguration"',
        "invert": True,  # flag if pattern is ABSENT and bucket exists
        "description": "S3 bucket does not have versioning configured",
        "remediation": "Add VersioningConfiguration with Status: Enabled",
    },
    {
        "id": "CF002", "name": "Unrestricted Security Group", "severity": "critical",
        "pattern": r'"CidrIp"\s*:\s*"0\.0\.0\.0/0"',
        "description": "Security group allows unrestricted ingress from 0.0.0.0/0",
        "remediation": "Restrict CidrIp to specific IP ranges",
    },
    {
        "id": "CF003", "name": "RDS Publicly Accessible", "severity": "critical",
        "pattern": r'"PubliclyAccessible"\s*:\s*true',
        "description": "RDS instance is publicly accessible",
        "remediation": "Set PubliclyAccessible to false",
    },
    {
        "id": "CF004", "name": "No Deletion Policy", "severity": "medium",
        "pattern": r'"DeletionPolicy"',
        "invert": True,
        "description": "Resource lacks explicit DeletionPolicy",
        "remediation": "Add DeletionPolicy: Retain for critical resources",
    },
]


# ── File type detection ────────────────────────────────────────────────────────

def _detect_iac_type(filename: str, content: str, hint: str = "auto") -> str:
    """Return 'terraform', 'kubernetes', 'dockerfile', 'cloudformation', or 'unknown'."""
    if hint != "auto":
        return hint

    name_lower = filename.lower()
    base = Path(filename).name.lower()

    # Dockerfile
    if base in ("dockerfile", "containerfile") or name_lower.endswith(".dockerfile"):
        return "dockerfile"

    # Terraform
    if name_lower.endswith(".tf") or name_lower.endswith(".tfvars"):
        return "terraform"

    # CloudFormation (JSON)
    if name_lower.endswith(".json"):
        if "AWSTemplateFormatVersion" in content or '"Resources"' in content:
            return "cloudformation"
        return "unknown"

    # YAML-based
    if name_lower.endswith((".yaml", ".yml")):
        if "AWSTemplateFormatVersion" in content:
            return "cloudformation"
        if re.search(r'^apiVersion\s*:', content, re.MULTILINE):
            return "kubernetes"
        return "unknown"

    return "unknown"


# ── Check implementations ─────────────────────────────────────────────────────

def _run_terraform_checks(content: str, filename: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    for check in TERRAFORM_CHECKS:
        pattern = re.compile(check["pattern"], re.IGNORECASE | re.DOTALL)
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                snippet = line.strip()
                findings.append({
                    "check_id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "filename": filename,
                    "line": i,
                    "description": check["description"],
                    "remediation": check["remediation"],
                    "code_snippet": snippet,
                })
    return findings


def _run_dockerfile_checks(content: str, filename: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    has_healthcheck = any(l.strip().upper().startswith("HEALTHCHECK") for l in lines)

    for check in DOCKERFILE_CHECKS:
        if check.get("check") == "noHealthcheck":
            if not has_healthcheck:
                findings.append({
                    "check_id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "filename": filename,
                    "line": len(lines),
                    "description": check["description"],
                    "remediation": check["remediation"],
                    "code_snippet": "(no HEALTHCHECK found)",
                })
            continue

        pattern = re.compile(check["pattern"], re.IGNORECASE | re.MULTILINE)
        for i, line in enumerate(lines, 1):
            if pattern.search(line.strip()):
                findings.append({
                    "check_id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "filename": filename,
                    "line": i,
                    "description": check["description"],
                    "remediation": check["remediation"],
                    "code_snippet": line.strip(),
                })
    return findings


def _run_kubernetes_checks(content: str, filename: str) -> list[dict]:
    findings = []
    try:
        import yaml as _yaml
        docs = list(_yaml.safe_load_all(content))
    except Exception:
        return findings

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "")
        spec = doc.get("spec", {}) or {}

        # K8S001 — runs as root
        security_ctx = spec.get("securityContext", {}) or {}
        if security_ctx.get("runAsUser") == 0 or security_ctx.get("runAsNonRoot") is False:
            findings.append({
                "check_id": "K8S001", "name": "Container Runs as Root",
                "severity": "high", "filename": filename, "line": 1,
                "description": "Pod/container configured to run as root user",
                "remediation": "Set securityContext.runAsNonRoot: true and runAsUser: 1000",
                "code_snippet": f"kind: {kind} — runAsUser: 0 or runAsNonRoot: false",
            })

        containers = spec.get("containers", []) or []
        for c in containers:
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "unnamed")
            c_sec = c.get("securityContext", {}) or {}

            # K8S002 — privileged
            if c_sec.get("privileged") is True:
                findings.append({
                    "check_id": "K8S002", "name": "Privileged Container",
                    "severity": "critical", "filename": filename, "line": 1,
                    "description": f"Container '{c_name}' is running in privileged mode",
                    "remediation": "Remove privileged: true from securityContext",
                    "code_snippet": f"container: {c_name} — securityContext.privileged: true",
                })

            # K8S003 — no resource limits
            resources = c.get("resources", {}) or {}
            if not resources.get("limits"):
                findings.append({
                    "check_id": "K8S003", "name": "No Resource Limits",
                    "severity": "medium", "filename": filename, "line": 1,
                    "description": f"Container '{c_name}' has no CPU/memory resource limits",
                    "remediation": "Add resources.limits.cpu and resources.limits.memory",
                    "code_snippet": f"container: {c_name} — no resources.limits defined",
                })

            # K8S006 — latest tag
            image = c.get("image", "")
            if image.endswith(":latest") or (":" not in image and image):
                findings.append({
                    "check_id": "K8S006", "name": "Image Tag is Latest",
                    "severity": "medium", "filename": filename, "line": 1,
                    "description": f"Container '{c_name}' uses :latest or untagged image",
                    "remediation": "Pin image to a specific version tag or digest",
                    "code_snippet": f"image: {image}",
                })

            # K8S007 — secret in env var
            for env in (c.get("env") or []):
                if not isinstance(env, dict):
                    continue
                env_name = env.get("name", "").upper()
                env_val = str(env.get("value", "") or "")
                if any(kw in env_name for kw in ("PASSWORD", "SECRET", "KEY", "TOKEN", "API_KEY")):
                    if env_val and "secretKeyRef" not in str(env):
                        findings.append({
                            "check_id": "K8S007", "name": "Secret in Environment Variable",
                            "severity": "high", "filename": filename, "line": 1,
                            "description": f"Container '{c_name}' has hardcoded secret in env var {env_name}",
                            "remediation": "Use Kubernetes Secrets or external secret manager",
                            "code_snippet": f"env: {env_name}={env_val[:30]}...",
                        })

        # K8S004 — hostPath volumes
        volumes = spec.get("volumes", []) or []
        for v in volumes:
            if isinstance(v, dict) and v.get("hostPath"):
                findings.append({
                    "check_id": "K8S004", "name": "HostPath Volume Mount",
                    "severity": "high", "filename": filename, "line": 1,
                    "description": f"Volume '{v.get('name', 'unnamed')}' uses hostPath — potential container escape",
                    "remediation": "Avoid hostPath volumes; use PersistentVolumeClaims instead",
                    "code_snippet": f"volume: {v.get('name')} — hostPath: {v['hostPath'].get('path', '')}",
                })

        # K8S005 — no NetworkPolicy (flag for Namespace or Deployment kinds)
        if kind in ("Deployment", "DaemonSet", "StatefulSet"):
            # Simple heuristic: flag awareness
            findings.append({
                "check_id": "K8S005", "name": "No Network Policy",
                "severity": "medium", "filename": filename, "line": 1,
                "description": f"{kind} found — verify a NetworkPolicy exists for this namespace",
                "remediation": "Create NetworkPolicy resources to restrict pod-to-pod traffic",
                "code_snippet": f"kind: {kind} — no NetworkPolicy verified",
            })

    return findings


def _run_cloudformation_checks(content: str, filename: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    for check in CLOUDFORMATION_CHECKS:
        if check.get("invert"):
            # Skip invert checks (complex — would need full AST parse)
            continue
        pattern = re.compile(check["pattern"], re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                findings.append({
                    "check_id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "filename": filename,
                    "line": i,
                    "description": check["description"],
                    "remediation": check["remediation"],
                    "code_snippet": line.strip(),
                })
    return findings


def _run_checks(content: str, filename: str, iac_type: str) -> list[dict]:
    if iac_type == "terraform":
        return _run_terraform_checks(content, filename)
    if iac_type == "kubernetes":
        return _run_kubernetes_checks(content, filename)
    if iac_type == "dockerfile":
        return _run_dockerfile_checks(content, filename)
    if iac_type == "cloudformation":
        return _run_cloudformation_checks(content, filename)
    return []


def _run_checkov(tmp_dir: str) -> list[dict]:
    """Run Checkov if installed and parse JSON output."""
    extra: list[dict] = []
    try:
        result = subprocess.run(
            ["checkov", "-d", tmp_dir, "--output", "json", "--quiet"],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout or "{}")
        for res in (data if isinstance(data, list) else [data]):
            for check in res.get("results", {}).get("failed_checks", []):
                extra.append({
                    "check_id": check.get("check_id", "CKV_UNKNOWN"),
                    "name": check.get("check", {}).get("name", "Checkov Finding"),
                    "severity": "medium",
                    "filename": Path(check.get("repo_file_path", "")).name,
                    "line": check.get("file_line_range", [1])[0],
                    "description": check.get("check", {}).get("name", ""),
                    "remediation": check.get("check", {}).get("guideline", "See Checkov docs"),
                    "code_snippet": "\n".join(check.get("code_block", [["", ""]])[0]) if check.get("code_block") else "",
                    "source": "checkov",
                })
    except Exception:
        pass
    return extra


# ── SSE helpers ───────────────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


# ── Upload filename sanitization ──────────────────────────────────────────────
# Mirrors the pattern used by nuclei.py's upload_template: strip any directory
# components with os.path.basename() (attacker-controlled multipart filenames
# must never be trusted — a value like "/etc/cron.d/pwn" or "../../x" would
# otherwise let pathlib's "/" operator escape the intended temp directory
# entirely), then allowlist the remaining characters. Anything that doesn't
# survive is replaced with a safe synthetic name.

_SAFE_FILENAME_RE = re.compile(r'^[a-zA-Z0-9_\-.]+$')


def _sanitize_upload_filename(raw_name: str | None, index: int, used_names: set[str]) -> str:
    name = os.path.basename((raw_name or "").strip())

    # Preserve a plausible extension (helps _detect_iac_type / Checkov) if safe.
    ext = ""
    if "." in name:
        candidate_ext = name.rsplit(".", 1)[-1].lower()
        if re.match(r'^[a-zA-Z0-9]{1,10}$', candidate_ext):
            ext = candidate_ext

    if not name or name in (".", "..") or not _SAFE_FILENAME_RE.match(name):
        name = f"file_{index}.{ext}" if ext else f"file_{index}"

    # De-duplicate collisions after sanitization (e.g. two uploads whose
    # names both sanitize down to the same string) rather than silently
    # overwriting a previously-written file.
    base_name = name
    counter = 1
    while name in used_names:
        if "." in base_name:
            stem, _, e = base_name.rpartition(".")
            name = f"{stem}_{counter}.{e}"
        else:
            name = f"{base_name}_{counter}"
        counter += 1
    used_names.add(name)
    return name


# ── Scan generator ────────────────────────────────────────────────────────────

async def _scan_generator(
    files: list[UploadFile],
    iac_type_hint: str,
    severity_threshold: str,
    org_id: str,
    scan_id: str,
) -> AsyncGenerator[str, None]:
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
    threshold_idx = SEVERITY_ORDER.index(severity_threshold) if severity_threshold in SEVERITY_ORDER else 3

    started_at = datetime.now(timezone.utc).isoformat()
    all_findings: list[dict] = []
    files_scanned = 0
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    tmp_dir = tempfile.mkdtemp(prefix="iac_scan_")
    tmp_dir_resolved = Path(tmp_dir).resolve()
    used_names: set[str] = set()

    try:
        for upload in files:
            raw = await upload.read()

            # Sanitize the client-supplied filename before it ever touches
            # the filesystem — see _sanitize_upload_filename above.
            filename = _sanitize_upload_filename(upload.filename, files_scanned, used_names)

            # Save to temp dir for Checkov
            tmp_path = (Path(tmp_dir) / filename).resolve()
            if tmp_path != tmp_dir_resolved and tmp_dir_resolved not in tmp_path.parents:
                # Defense in depth: sanitization above should make this
                # unreachable, but never write outside the intended dir.
                raise ValueError(f"Rejected unsafe upload filename: {upload.filename!r}")
            tmp_path.write_bytes(raw)

            try:
                content = raw.decode("utf-8", errors="replace")
            except Exception:
                content = ""

            detected = _detect_iac_type(filename, content, iac_type_hint)
            yield _sse("file_start", {"filename": filename, "iac_type": detected})
            await asyncio.sleep(0)

            findings = _run_checks(content, filename, detected)

            file_findings = 0
            for f in findings:
                sev = f.get("severity", "low")
                sev_idx = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 3
                if sev_idx <= threshold_idx:
                    yield _sse("finding", f)
                    by_severity[sev] = by_severity.get(sev, 0) + 1
                    all_findings.append(f)
                    file_findings += 1
                    await asyncio.sleep(0)

            yield _sse("file_complete", {"filename": filename, "iac_type": detected, "findings": file_findings})
            files_scanned += 1
            await asyncio.sleep(0)

        # Checkov pass
        if shutil.which("checkov"):
            yield _sse("phase", {"phase": "checkov", "message": "Running Checkov analysis..."})
            await asyncio.sleep(0)
            loop = asyncio.get_event_loop()
            checkov_findings = await loop.run_in_executor(None, _run_checkov, tmp_dir)
            for f in checkov_findings:
                sev = f.get("severity", "medium")
                yield _sse("finding", f)
                by_severity[sev] = by_severity.get(sev, 0) + 1
                all_findings.append(f)
                await asyncio.sleep(0)

        completed_at = datetime.now(timezone.utc).isoformat()
        summary = {
            "id": scan_id,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "by_severity": by_severity,
        }
        yield _sse("complete", summary)

        # Persist
        record = {
            "id": scan_id,
            "started_at": started_at,
            "completed_at": completed_at,
            "iac_type": iac_type_hint,
            "severity_threshold": severity_threshold,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "findings": all_findings,
        }
        _save_scan_result(org_id, record)

    except Exception as exc:
        yield _sse("error", {"message": str(exc)})
    finally:
        # Clean up temp dir
        import shutil as _shutil
        _shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/history")
async def get_history(
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
):
    return _load_history(org_id)


@router.get("/history/{scan_id}")
async def get_scan(
    scan_id: str,
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
):
    record = _load_scan(org_id, scan_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}")
async def delete_scan(
    scan_id: str,
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
):
    if not _delete_scan(org_id, scan_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return {"deleted": True}


@router.post("/scan")
async def scan_iac(
    files: list[UploadFile],
    iac_type: str = Form("auto"),
    severity_threshold: str = Form("low"),
    org_id: Annotated[str, Depends(get_current_org_id)] = None,
    current_user: Annotated[User, Depends(get_current_user)] = None,
):
    if not files:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No files provided")

    scan_id = str(_uuid_mod.uuid4())
    target = ", ".join(f.filename for f in files if f.filename) or f"{len(files)} file(s)"
    from app.services.scan_activity import tee_scan_activity
    return StreamingResponse(
        tee_scan_activity(org_id, "iac_scanner", target, scan_id, _scan_generator(files, iac_type, severity_threshold, org_id, scan_id)),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/checks")
async def list_checks(
    _user: Annotated[User, Depends(get_current_user)],
):
    return {
        "terraform": [
            {"id": c["id"], "name": c["name"], "severity": c["severity"], "description": c["description"]}
            for c in TERRAFORM_CHECKS
        ],
        "kubernetes": [
            {"id": c["id"], "name": c["name"], "severity": c["severity"], "description": c["description"]}
            for c in KUBERNETES_CHECKS
        ],
        "dockerfile": [
            {"id": c["id"], "name": c["name"], "severity": c["severity"], "description": c["description"]}
            for c in DOCKERFILE_CHECKS
        ],
        "cloudformation": [
            {"id": c["id"], "name": c["name"], "severity": c["severity"], "description": c["description"]}
            for c in CLOUDFORMATION_CHECKS
        ],
    }
