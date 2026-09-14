"""
CSPM (Cloud Security Posture Management) Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Runs 21+ native AWS checks via boto3 with concurrent execution.
Prowler CLI is used automatically if installed.

Credentials are used per-request and never stored or logged.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
import uuid as _uuid_mod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator
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
from app.services.finding_ingest import ingest_findings

# ── Optional boto3 ────────────────────────────────────────────────────────────
try:
    import boto3  # type: ignore[import]
    import botocore.exceptions  # type: ignore[import]
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False

# ── Scan history storage (filesystem) ────────────────────────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "cspm" / org_id
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

router = APIRouter(prefix="/cspm", tags=["CSPM Scanner"])

# ── Check catalogue ───────────────────────────────────────────────────────────

AWS_CHECKS: list[dict] = [
    # S3
    {"id": "s3_bucket_public_read",    "name": "S3 Bucket Public Read Access",              "severity": "critical", "category": "S3"},
    {"id": "s3_bucket_public_write",   "name": "S3 Bucket Public Write Access",             "severity": "critical", "category": "S3"},
    {"id": "s3_bucket_no_mfa_delete",  "name": "S3 Bucket MFA Delete Not Enabled",          "severity": "medium",   "category": "S3"},
    {"id": "s3_bucket_no_versioning",  "name": "S3 Bucket Versioning Disabled",             "severity": "low",      "category": "S3"},
    {"id": "s3_bucket_no_encryption",  "name": "S3 Bucket Server-Side Encryption Disabled", "severity": "high",     "category": "S3"},
    # IAM
    {"id": "iam_root_access_key",      "name": "Root Account Has Access Key",               "severity": "critical", "category": "IAM"},
    {"id": "iam_mfa_not_enabled",      "name": "IAM User Without MFA",                      "severity": "high",     "category": "IAM"},
    {"id": "iam_admin_policy_attached","name": "Overly Permissive IAM Policy (AdministratorAccess)", "severity": "high", "category": "IAM"},
    {"id": "iam_password_policy_weak", "name": "IAM Password Policy Too Weak",              "severity": "medium",   "category": "IAM"},
    # EC2 / Security Groups
    {"id": "ec2_sg_open_ssh",          "name": "Security Group Allows SSH from 0.0.0.0/0", "severity": "critical", "category": "EC2"},
    {"id": "ec2_sg_open_rdp",          "name": "Security Group Allows RDP from 0.0.0.0/0", "severity": "critical", "category": "EC2"},
    {"id": "ec2_sg_open_all",          "name": "Security Group Allows All Traffic from 0.0.0.0/0", "severity": "critical", "category": "EC2"},
    {"id": "ec2_instance_public_ip",   "name": "EC2 Instance Has Public IP",                "severity": "low",      "category": "EC2"},
    {"id": "ec2_ebs_not_encrypted",    "name": "EBS Volume Not Encrypted",                  "severity": "medium",   "category": "EC2"},
    # RDS
    {"id": "rds_public",               "name": "RDS Instance Publicly Accessible",          "severity": "critical", "category": "RDS"},
    {"id": "rds_no_encryption",        "name": "RDS Instance Not Encrypted",                "severity": "high",     "category": "RDS"},
    {"id": "rds_no_backup",            "name": "RDS Automated Backup Disabled",             "severity": "medium",   "category": "RDS"},
    # CloudTrail
    {"id": "cloudtrail_not_enabled",   "name": "CloudTrail Not Enabled",                   "severity": "high",     "category": "CloudTrail"},
    {"id": "cloudtrail_not_multiregion","name": "CloudTrail Not Multi-Region",              "severity": "medium",   "category": "CloudTrail"},
    # KMS
    {"id": "kms_key_rotation_disabled","name": "KMS Key Rotation Disabled",                 "severity": "medium",   "category": "KMS"},
    # Lambda
    {"id": "lambda_env_vars_secrets",  "name": "Lambda Function Has Secrets in Environment Variables", "severity": "high", "category": "Lambda"},
]

CHECK_CATEGORIES = sorted({c["category"] for c in AWS_CHECKS})

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Pydantic schemas ──────────────────────────────────────────────────────────

class CSPMScanRequest(BaseModel):
    provider: str  # "aws", "azure", "gcp", "kubernetes"
    # AWS
    aws_access_key: str | None = None
    aws_secret_key: str | None = None
    aws_region: str = "us-east-1"
    aws_session_token: str | None = None
    # GCP
    gcp_project_id: str | None = None
    gcp_service_account_key: str | None = None
    # Azure
    azure_subscription_id: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    # Kubernetes
    k8s_api_server: str | None = None
    k8s_token: str | None = None
    k8s_ca_cert: str | None = None  # PEM; when omitted, the system trust store is used
    k8s_insecure_skip_tls_verify: bool = False  # explicit opt-in only — never a silent default
    # Filters
    categories: list[str] = []
    severity_filter: str = "medium"  # minimum severity


# ── Helper: build boto3 session ───────────────────────────────────────────────

def _make_boto_session(req: CSPMScanRequest):
    """Return a boto3 Session built from request credentials (never logged)."""
    kwargs: dict = {"region_name": req.aws_region}
    if req.aws_access_key and req.aws_secret_key:
        kwargs["aws_access_key_id"] = req.aws_access_key
        kwargs["aws_secret_access_key"] = req.aws_secret_key
        if req.aws_session_token:
            kwargs["aws_session_token"] = req.aws_session_token
    return boto3.Session(**kwargs)


# ── Remediation text ─────────────────────────────────────────────────────────

_REMEDIATION: dict[str, str] = {
    "s3_bucket_public_read":     "Remove the public ACL and set S3 Block Public Access on the bucket.",
    "s3_bucket_public_write":    "Remove the public write ACL and enable S3 Block Public Access.",
    "s3_bucket_no_mfa_delete":   "Enable MFA Delete on the bucket versioning configuration.",
    "s3_bucket_no_versioning":   "Enable versioning on the S3 bucket.",
    "s3_bucket_no_encryption":   "Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
    "iam_root_access_key":       "Delete root account access keys immediately and use IAM roles instead.",
    "iam_mfa_not_enabled":       "Enforce MFA for all IAM users via an IAM policy condition.",
    "iam_admin_policy_attached": "Replace AdministratorAccess with least-privilege policies.",
    "iam_password_policy_weak":  "Configure a strong IAM account password policy (min 14 chars, complexity, rotation).",
    "ec2_sg_open_ssh":           "Restrict SSH (port 22) to known IP ranges; use AWS Systems Manager Session Manager.",
    "ec2_sg_open_rdp":           "Restrict RDP (port 3389) to known IP ranges; use a bastion host or VPN.",
    "ec2_sg_open_all":           "Remove 0.0.0.0/0 allow-all rules; apply least-privilege security group rules.",
    "ec2_instance_public_ip":    "Place instances in private subnets and route outbound traffic via NAT Gateway.",
    "ec2_ebs_not_encrypted":     "Enable EBS encryption at rest using AWS KMS.",
    "rds_public":                "Disable 'Publicly Accessible' on the RDS instance and move it to a private subnet.",
    "rds_no_encryption":         "Enable encryption at rest for the RDS instance (requires a snapshot restore).",
    "rds_no_backup":             "Enable automated backups with a retention period of at least 7 days.",
    "cloudtrail_not_enabled":    "Create a CloudTrail trail covering all regions with log file validation enabled.",
    "cloudtrail_not_multiregion":"Enable the IsMultiRegionTrail flag on your CloudTrail trail.",
    "kms_key_rotation_disabled": "Enable automatic key rotation on the KMS customer-managed key.",
    "lambda_env_vars_secrets":   "Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them at runtime.",
}


# ── Native AWS checks (boto3) ─────────────────────────────────────────────────

def _run_aws_check(check_id: str, session) -> list[dict]:
    """Execute a single AWS check synchronously. Returns list of findings."""
    findings: list[dict] = []

    def _finding(resource: str, arn: str, description: str, severity: str) -> dict:
        return {
            "check_id": check_id,
            "severity": severity,
            "resource": resource,
            "resource_arn": arn,
            "description": description,
            "remediation": _REMEDIATION.get(check_id, "Review AWS security best practices."),
        }

    try:
        # ── S3 ─────────────────────────────────────────────────────────────
        if check_id.startswith("s3_"):
            s3 = session.client("s3")
            try:
                buckets = s3.list_buckets().get("Buckets", [])
            except Exception:
                return findings

            for b in buckets:
                name = b["Name"]
                arn = f"arn:aws:s3:::{name}"

                if check_id == "s3_bucket_public_read":
                    try:
                        acl = s3.get_bucket_acl(Bucket=name)
                        for grant in acl.get("Grants", []):
                            grantee = grant.get("Grantee", {})
                            uri = grantee.get("URI", "")
                            perm = grant.get("Permission", "")
                            if "AllUsers" in uri and perm in ("READ", "FULL_CONTROL"):
                                findings.append(_finding(name, arn, f"Bucket {name} grants public READ access via ACL.", "critical"))
                    except Exception:
                        pass
                    try:
                        pol_status = s3.get_bucket_policy_status(Bucket=name)
                        if pol_status.get("PolicyStatus", {}).get("IsPublic"):
                            findings.append(_finding(name, arn, f"Bucket {name} has a public bucket policy.", "critical"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_public_write":
                    try:
                        acl = s3.get_bucket_acl(Bucket=name)
                        for grant in acl.get("Grants", []):
                            uri = grant.get("Grantee", {}).get("URI", "")
                            perm = grant.get("Permission", "")
                            if "AllUsers" in uri and perm in ("WRITE", "WRITE_ACP", "FULL_CONTROL"):
                                findings.append(_finding(name, arn, f"Bucket {name} grants public WRITE access via ACL.", "critical"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_no_mfa_delete":
                    try:
                        ver = s3.get_bucket_versioning(Bucket=name)
                        if ver.get("MFADelete", "Disabled") != "Enabled":
                            findings.append(_finding(name, arn, f"Bucket {name} does not have MFA Delete enabled.", "medium"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_no_versioning":
                    try:
                        ver = s3.get_bucket_versioning(Bucket=name)
                        if ver.get("Status", "Suspended") != "Enabled":
                            findings.append(_finding(name, arn, f"Bucket {name} does not have versioning enabled.", "low"))
                    except Exception:
                        pass

                elif check_id == "s3_bucket_no_encryption":
                    try:
                        s3.get_bucket_encryption(Bucket=name)
                    except s3.exceptions.ClientError if hasattr(s3, "exceptions") else Exception:
                        findings.append(_finding(name, arn, f"Bucket {name} has no default server-side encryption.", "high"))
                    except Exception:
                        findings.append(_finding(name, arn, f"Bucket {name} has no default server-side encryption.", "high"))

        # ── IAM ─────────────────────────────────────────────────────────────
        elif check_id.startswith("iam_"):
            iam = session.client("iam")

            if check_id == "iam_root_access_key":
                try:
                    summary = iam.get_account_summary()["SummaryMap"]
                    if summary.get("AccountAccessKeysPresent", 0) > 0:
                        findings.append(_finding("root", "arn:aws:iam::root", "Root account has active access keys.", "critical"))
                except Exception:
                    pass

            elif check_id == "iam_mfa_not_enabled":
                try:
                    paginator = iam.get_paginator("list_users")
                    for page in paginator.paginate():
                        for user in page["Users"]:
                            uname = user["UserName"]
                            mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                            if not mfa_devices:
                                arn = user["Arn"]
                                findings.append(_finding(uname, arn, f"IAM user {uname} has no MFA device.", "high"))
                except Exception:
                    pass

            elif check_id == "iam_admin_policy_attached":
                try:
                    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
                    paginator = iam.get_paginator("list_entities_for_policy")
                    for page in paginator.paginate(PolicyArn=admin_arn):
                        for u in page.get("PolicyUsers", []):
                            findings.append(_finding(u["UserName"], u["UserId"], f"User {u['UserName']} has AdministratorAccess.", "high"))
                        for g in page.get("PolicyGroups", []):
                            findings.append(_finding(g["GroupName"], g["GroupId"], f"Group {g['GroupName']} has AdministratorAccess.", "high"))
                        for r in page.get("PolicyRoles", []):
                            findings.append(_finding(r["RoleName"], r["RoleId"], f"Role {r['RoleName']} has AdministratorAccess.", "high"))
                except Exception:
                    pass

            elif check_id == "iam_password_policy_weak":
                try:
                    pol = iam.get_account_password_policy()["PasswordPolicy"]
                    issues = []
                    if pol.get("MinimumPasswordLength", 0) < 14:
                        issues.append("min length < 14")
                    if not pol.get("RequireUppercaseCharacters"):
                        issues.append("no uppercase requirement")
                    if not pol.get("RequireLowercaseCharacters"):
                        issues.append("no lowercase requirement")
                    if not pol.get("RequireNumbers"):
                        issues.append("no number requirement")
                    if not pol.get("RequireSymbols"):
                        issues.append("no symbol requirement")
                    if issues:
                        findings.append(_finding("account", "arn:aws:iam::password-policy", f"Password policy issues: {', '.join(issues)}.", "medium"))
                except Exception:
                    # No password policy set at all
                    findings.append(_finding("account", "arn:aws:iam::password-policy", "No IAM account password policy is configured.", "medium"))

        # ── EC2 / Security Groups ───────────────────────────────────────────
        elif check_id.startswith("ec2_sg_"):
            ec2 = session.client("ec2")
            try:
                paginator = ec2.get_paginator("describe_security_groups")
                for page in paginator.paginate():
                    for sg in page["SecurityGroups"]:
                        sg_id = sg["GroupId"]
                        sg_name = sg.get("GroupName", sg_id)
                        arn = f"arn:aws:ec2:{session.region_name}::security-group/{sg_id}"
                        for rule in sg.get("IpPermissions", []):
                            from_port = rule.get("FromPort", -1)
                            to_port = rule.get("ToPort", -1)
                            for ip_range in rule.get("IpRanges", []) + rule.get("Ipv6Ranges", []):
                                cidr = ip_range.get("CidrIp") or ip_range.get("CidrIpv6", "")
                                if cidr in ("0.0.0.0/0", "::/0"):
                                    if check_id == "ec2_sg_open_ssh" and from_port <= 22 <= to_port:
                                        findings.append(_finding(sg_name, arn, f"SG {sg_name} allows SSH from {cidr}.", "critical"))
                                    elif check_id == "ec2_sg_open_rdp" and from_port <= 3389 <= to_port:
                                        findings.append(_finding(sg_name, arn, f"SG {sg_name} allows RDP from {cidr}.", "critical"))
                                    elif check_id == "ec2_sg_open_all" and from_port == -1 and to_port == -1:
                                        findings.append(_finding(sg_name, arn, f"SG {sg_name} allows all traffic from {cidr}.", "critical"))
            except Exception:
                pass

        elif check_id == "ec2_instance_public_ip":
            ec2 = session.client("ec2")
            try:
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate():
                    for r in page["Reservations"]:
                        for inst in r["Instances"]:
                            if inst.get("PublicIpAddress") and inst.get("State", {}).get("Name") == "running":
                                iid = inst["InstanceId"]
                                arn = f"arn:aws:ec2:{session.region_name}::instance/{iid}"
                                findings.append(_finding(iid, arn, f"Instance {iid} has public IP {inst['PublicIpAddress']}.", "low"))
            except Exception:
                pass

        elif check_id == "ec2_ebs_not_encrypted":
            ec2 = session.client("ec2")
            try:
                paginator = ec2.get_paginator("describe_volumes")
                for page in paginator.paginate():
                    for vol in page["Volumes"]:
                        if not vol.get("Encrypted"):
                            vid = vol["VolumeId"]
                            arn = f"arn:aws:ec2:{session.region_name}::volume/{vid}"
                            findings.append(_finding(vid, arn, f"EBS volume {vid} is not encrypted.", "medium"))
            except Exception:
                pass

        # ── RDS ─────────────────────────────────────────────────────────────
        elif check_id.startswith("rds_"):
            rds = session.client("rds")
            try:
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page["DBInstances"]:
                        did = db["DBInstanceIdentifier"]
                        arn = db["DBInstanceArn"]
                        if check_id == "rds_public" and db.get("PubliclyAccessible"):
                            findings.append(_finding(did, arn, f"RDS instance {did} is publicly accessible.", "critical"))
                        elif check_id == "rds_no_encryption" and not db.get("StorageEncrypted"):
                            findings.append(_finding(did, arn, f"RDS instance {did} storage is not encrypted.", "high"))
                        elif check_id == "rds_no_backup" and db.get("BackupRetentionPeriod", 0) == 0:
                            findings.append(_finding(did, arn, f"RDS instance {did} has automated backup disabled.", "medium"))
            except Exception:
                pass

        # ── CloudTrail ───────────────────────────────────────────────────────
        elif check_id.startswith("cloudtrail_"):
            ct = session.client("cloudtrail")
            try:
                trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
                if check_id == "cloudtrail_not_enabled":
                    if not trails:
                        findings.append(_finding("account", "arn:aws:cloudtrail::trail", "No CloudTrail trails are configured.", "high"))
                    else:
                        for t in trails:
                            status_resp = ct.get_trail_status(Name=t["TrailARN"])
                            if not status_resp.get("IsLogging"):
                                findings.append(_finding(t["Name"], t["TrailARN"], f"CloudTrail trail {t['Name']} is not logging.", "high"))
                elif check_id == "cloudtrail_not_multiregion":
                    if not trails:
                        findings.append(_finding("account", "arn:aws:cloudtrail::trail", "No CloudTrail trails configured.", "medium"))
                    else:
                        for t in trails:
                            if not t.get("IsMultiRegionTrail"):
                                findings.append(_finding(t["Name"], t["TrailARN"], f"CloudTrail trail {t['Name']} is not multi-region.", "medium"))
            except Exception:
                pass

        # ── KMS ─────────────────────────────────────────────────────────────
        elif check_id == "kms_key_rotation_disabled":
            kms = session.client("kms")
            try:
                paginator = kms.get_paginator("list_keys")
                for page in paginator.paginate():
                    for key in page["Keys"]:
                        kid = key["KeyId"]
                        try:
                            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                            if meta.get("KeyManager") != "AWS" and meta.get("KeyState") == "Enabled":
                                rotation = kms.get_key_rotation_status(KeyId=kid)
                                if not rotation.get("KeyRotationEnabled"):
                                    arn = meta["Arn"]
                                    alias = meta.get("Description", kid)[:40]
                                    findings.append(_finding(alias, arn, f"KMS key {kid} does not have automatic rotation enabled.", "medium"))
                        except Exception:
                            pass
            except Exception:
                pass

        # ── Lambda ───────────────────────────────────────────────────────────
        elif check_id == "lambda_env_vars_secrets":
            lm = session.client("lambda")
            SECRET_PATTERNS = ["secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "access_key"]
            try:
                paginator = lm.get_paginator("list_functions")
                for page in paginator.paginate():
                    for fn in page["Functions"]:
                        fname = fn["FunctionName"]
                        arn = fn["FunctionArn"]
                        env_vars = fn.get("Environment", {}).get("Variables", {})
                        for k in env_vars:
                            if any(p in k.lower() for p in SECRET_PATTERNS):
                                findings.append(_finding(fname, arn, f"Lambda function {fname} has a suspicious env var: {k}.", "high"))
                                break
            except Exception:
                pass

    except Exception:
        # Broad catch — never surface credential errors to logs
        pass

    return findings


# ── GCP checks (REST via httpx + google-auth token minting) ─────────────────

GCP_CHECKS: list[dict] = [
    {"id": "gcp_storage_bucket_public",       "name": "GCS Bucket Publicly Accessible",              "severity": "critical", "category": "Storage"},
    {"id": "gcp_storage_bucket_no_ubla",      "name": "GCS Bucket Missing Uniform Bucket-Level Access", "severity": "low",  "category": "Storage"},
    {"id": "gcp_iam_overly_permissive",       "name": "Project IAM Policy Overly Permissive",        "severity": "critical", "category": "IAM"},
    {"id": "gcp_iam_sa_key_age",              "name": "Service Account Key Older Than 90 Days",      "severity": "medium",   "category": "IAM"},
    {"id": "gcp_firewall_open_ssh",           "name": "Firewall Rule Allows SSH from 0.0.0.0/0",     "severity": "critical", "category": "Network"},
    {"id": "gcp_firewall_open_rdp",           "name": "Firewall Rule Allows RDP from 0.0.0.0/0",     "severity": "critical", "category": "Network"},
    {"id": "gcp_firewall_open_all",           "name": "Firewall Rule Allows All Traffic from 0.0.0.0/0", "severity": "critical", "category": "Network"},
    {"id": "gcp_compute_instance_public_ip",  "name": "Compute Instance Has Public IP",              "severity": "low",      "category": "Compute"},
    {"id": "gcp_sql_public_ip",               "name": "Cloud SQL Instance Publicly Accessible",      "severity": "critical", "category": "Database"},
    {"id": "gcp_sql_no_ssl",                  "name": "Cloud SQL Instance Does Not Require SSL",     "severity": "high",     "category": "Database"},
]

_GCP_REMEDIATION: dict[str, str] = {
    "gcp_storage_bucket_public":      "Remove allUsers/allAuthenticatedUsers bindings from the bucket IAM policy.",
    "gcp_storage_bucket_no_ubla":     "Enable uniform bucket-level access to disable legacy per-object ACLs.",
    "gcp_iam_overly_permissive":      "Replace broad roles/owner or roles/editor bindings on allUsers/allAuthenticatedUsers with least-privilege roles.",
    "gcp_iam_sa_key_age":             "Rotate the service account key and prefer workload identity federation over long-lived keys.",
    "gcp_firewall_open_ssh":          "Restrict SSH (22) to known IP ranges or use Identity-Aware Proxy for SSH.",
    "gcp_firewall_open_rdp":          "Restrict RDP (3389) to known IP ranges or use IAP TCP forwarding.",
    "gcp_firewall_open_all":         "Remove 0.0.0.0/0 allow-all firewall rules; apply least-privilege rules.",
    "gcp_compute_instance_public_ip":"Remove the external IP and route via Cloud NAT for outbound access.",
    "gcp_sql_public_ip":             "Disable public IP and use private IP / Cloud SQL Auth Proxy.",
    "gcp_sql_no_ssl":                "Enable 'Require SSL' on the Cloud SQL instance connection settings.",
}


def _gcp_access_token(service_account_json: str) -> str:
    """Mint an OAuth2 access token from a service-account JSON key (sync, run in executor)."""
    import google.auth.transport.requests
    from google.oauth2 import service_account

    info = json.loads(service_account_json)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


async def _run_gcp_check(check_id: str, project_id: str, token: str, client: "httpx.AsyncClient") -> list[dict]:
    """Execute a single GCP check via REST. Returns list of findings."""
    findings: list[dict] = []
    headers = {"Authorization": f"Bearer {token}"}

    def _finding(resource: str, resource_id: str, description: str, severity: str) -> dict:
        return {
            "check_id": check_id,
            "severity": severity,
            "resource": resource,
            "resource_arn": resource_id,
            "description": description,
            "remediation": _GCP_REMEDIATION.get(check_id, "Review GCP security best practices."),
        }

    try:
        if check_id.startswith("gcp_storage_bucket_"):
            resp = await client.get(
                "https://storage.googleapis.com/storage/v1/b",
                params={"project": project_id}, headers=headers,
            )
            if resp.status_code != 200:
                return findings
            for bucket in resp.json().get("items", []):
                name = bucket["name"]
                if check_id == "gcp_storage_bucket_public":
                    try:
                        iam_resp = await client.get(
                            f"https://storage.googleapis.com/storage/v1/b/{name}/iam", headers=headers,
                        )
                        for binding in iam_resp.json().get("bindings", []):
                            members = binding.get("members", [])
                            if "allUsers" in members or "allAuthenticatedUsers" in members:
                                findings.append(_finding(name, f"gcs/{name}", f"Bucket {name} grants access to {', '.join(m for m in members if 'all' in m.lower())}.", "critical"))
                    except Exception:
                        pass
                elif check_id == "gcp_storage_bucket_no_ubla":
                    ubla = bucket.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {})
                    if not ubla.get("enabled"):
                        findings.append(_finding(name, f"gcs/{name}", f"Bucket {name} does not have uniform bucket-level access enabled.", "low"))

        elif check_id == "gcp_iam_overly_permissive":
            resp = await client.post(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy",
                headers=headers, json={},
            )
            if resp.status_code == 200:
                for binding in resp.json().get("bindings", []):
                    role = binding.get("role", "")
                    members = binding.get("members", [])
                    if role in ("roles/owner", "roles/editor") and any(
                        m in ("allUsers", "allAuthenticatedUsers") for m in members
                    ):
                        findings.append(_finding(project_id, f"projects/{project_id}", f"Role {role} is bound to a public principal.", "critical"))

        elif check_id == "gcp_iam_sa_key_age":
            from datetime import datetime as _dt, timezone as _tz
            sa_resp = await client.get(
                f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts", headers=headers,
            )
            for sa in sa_resp.json().get("accounts", []):
                email = sa["email"]
                try:
                    keys_resp = await client.get(
                        f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts/{email}/keys",
                        headers=headers,
                    )
                    for key in keys_resp.json().get("keys", []):
                        if key.get("keyType") != "USER_MANAGED":
                            continue
                        valid_after = key.get("validAfterTime")
                        if valid_after:
                            created = _dt.fromisoformat(valid_after.replace("Z", "+00:00"))
                            age_days = (_dt.now(_tz.utc) - created).days
                            if age_days > 90:
                                findings.append(_finding(email, key["name"], f"Service account {email} has a key {age_days} days old.", "medium"))
                except Exception:
                    continue

        elif check_id.startswith("gcp_firewall_open_"):
            resp = await client.get(
                f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/firewalls",
                headers=headers,
            )
            for rule in resp.json().get("items", []):
                if rule.get("direction", "INGRESS") != "INGRESS" or rule.get("disabled"):
                    continue
                if "0.0.0.0/0" not in rule.get("sourceRanges", []):
                    continue
                name = rule["name"]
                for allowed in rule.get("allowed", []):
                    ports = allowed.get("ports", [])
                    proto = allowed.get("IPProtocol", "")
                    is_all = proto == "all" or not ports
                    has_port = lambda p: any(  # noqa: E731
                        p == pr or ("-" in pr and int(pr.split("-")[0]) <= p <= int(pr.split("-")[1]))
                        for pr in ports if pr.replace("-", "").isdigit()
                    )
                    if check_id == "gcp_firewall_open_ssh" and has_port(22):
                        findings.append(_finding(name, f"firewall/{name}", f"Firewall {name} allows SSH from 0.0.0.0/0.", "critical"))
                    elif check_id == "gcp_firewall_open_rdp" and has_port(3389):
                        findings.append(_finding(name, f"firewall/{name}", f"Firewall {name} allows RDP from 0.0.0.0/0.", "critical"))
                    elif check_id == "gcp_firewall_open_all" and is_all:
                        findings.append(_finding(name, f"firewall/{name}", f"Firewall {name} allows all traffic from 0.0.0.0/0.", "critical"))

        elif check_id == "gcp_compute_instance_public_ip":
            resp = await client.get(
                f"https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances",
                headers=headers,
            )
            for _zone, data in resp.json().get("items", {}).items():
                for inst in data.get("instances", []):
                    for iface in inst.get("networkInterfaces", []):
                        if iface.get("accessConfigs"):
                            findings.append(_finding(inst["name"], f"instance/{inst['name']}", f"Instance {inst['name']} has a public IP.", "low"))
                            break

        elif check_id.startswith("gcp_sql_"):
            resp = await client.get(
                f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}/instances", headers=headers,
            )
            for db in resp.json().get("items", []):
                name = db["name"]
                settings_ = db.get("settings", {})
                if check_id == "gcp_sql_public_ip":
                    for net in settings_.get("ipConfiguration", {}).get("authorizedNetworks", []):
                        if net.get("value") in ("0.0.0.0/0", "0.0.0.0"):
                            findings.append(_finding(name, f"sql/{name}", f"Cloud SQL instance {name} authorizes 0.0.0.0/0.", "critical"))
                    if settings_.get("ipConfiguration", {}).get("ipv4Enabled") and not settings_.get("ipConfiguration", {}).get("privateNetwork"):
                        findings.append(_finding(name, f"sql/{name}", f"Cloud SQL instance {name} has a public IP with no private network.", "critical"))
                elif check_id == "gcp_sql_no_ssl":
                    if not settings_.get("ipConfiguration", {}).get("requireSsl"):
                        findings.append(_finding(name, f"sql/{name}", f"Cloud SQL instance {name} does not require SSL.", "high"))

    except Exception:
        pass

    return findings


# ── Azure checks (REST via httpx + client-credentials OAuth2) ───────────────

AZURE_CHECKS: list[dict] = [
    {"id": "azure_storage_public_access",  "name": "Storage Account Allows Public Blob Access",     "severity": "critical", "category": "Storage"},
    {"id": "azure_storage_no_https_only",  "name": "Storage Account Does Not Enforce HTTPS",        "severity": "high",     "category": "Storage"},
    {"id": "azure_nsg_open_ssh",           "name": "NSG Allows SSH from Any Source",                "severity": "critical", "category": "Network"},
    {"id": "azure_nsg_open_rdp",           "name": "NSG Allows RDP from Any Source",                "severity": "critical", "category": "Network"},
    {"id": "azure_nsg_open_all",           "name": "NSG Allows All Traffic from Any Source",        "severity": "critical", "category": "Network"},
    {"id": "azure_sql_public_network",     "name": "SQL Server Allows Public Network Access",       "severity": "critical", "category": "Database"},
    {"id": "azure_sql_no_tde",             "name": "SQL Database Transparent Data Encryption Disabled", "severity": "high", "category": "Database"},
    {"id": "azure_keyvault_no_soft_delete","name": "Key Vault Soft Delete / Purge Protection Disabled", "severity": "high", "category": "KeyVault"},
    {"id": "azure_vm_no_disk_encryption",  "name": "VM Disk Encryption Not Enabled",                "severity": "medium",   "category": "Compute"},
]

_AZURE_REMEDIATION: dict[str, str] = {
    "azure_storage_public_access":   "Set 'Allow Blob public access' to disabled on the storage account.",
    "azure_storage_no_https_only":   "Enable 'Secure transfer required' (HTTPS-only) on the storage account.",
    "azure_nsg_open_ssh":            "Restrict SSH (22) to known IP ranges or use Azure Bastion.",
    "azure_nsg_open_rdp":            "Restrict RDP (3389) to known IP ranges or use Azure Bastion.",
    "azure_nsg_open_all":            "Remove any/any allow rules; apply least-privilege NSG rules.",
    "azure_sql_public_network":      "Disable public network access and use private endpoints.",
    "azure_sql_no_tde":              "Enable Transparent Data Encryption on the SQL database.",
    "azure_keyvault_no_soft_delete": "Enable soft-delete and purge protection on the Key Vault.",
    "azure_vm_no_disk_encryption":   "Enable Azure Disk Encryption on the virtual machine.",
}


async def _azure_access_token(tenant_id: str, client_id: str, client_secret: str, client: "httpx.AsyncClient") -> str:
    resp = await client.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://management.azure.com/.default",
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def _run_azure_check(check_id: str, subscription_id: str, token: str, client: "httpx.AsyncClient") -> list[dict]:
    """Execute a single Azure check via the ARM REST API. Returns list of findings."""
    findings: list[dict] = []
    headers = {"Authorization": f"Bearer {token}"}
    base = f"https://management.azure.com/subscriptions/{subscription_id}"
    api = {"storage": "2023-01-01", "network": "2023-05-01", "sql": "2021-11-01", "vault": "2023-07-01", "compute": "2023-07-01"}

    def _finding(resource: str, resource_id: str, description: str, severity: str) -> dict:
        return {
            "check_id": check_id,
            "severity": severity,
            "resource": resource,
            "resource_arn": resource_id,
            "description": description,
            "remediation": _AZURE_REMEDIATION.get(check_id, "Review Azure security best practices."),
        }

    try:
        if check_id.startswith("azure_storage_"):
            resp = await client.get(f"{base}/providers/Microsoft.Storage/storageAccounts", params={"api-version": api["storage"]}, headers=headers)
            for acct in resp.json().get("value", []):
                name = acct["name"]
                props = acct.get("properties", {})
                if check_id == "azure_storage_public_access" and props.get("allowBlobPublicAccess"):
                    findings.append(_finding(name, acct["id"], f"Storage account {name} allows public blob access.", "critical"))
                elif check_id == "azure_storage_no_https_only" and not props.get("supportsHttpsTrafficOnly", True):
                    findings.append(_finding(name, acct["id"], f"Storage account {name} does not enforce HTTPS-only traffic.", "high"))

        elif check_id.startswith("azure_nsg_open_"):
            resp = await client.get(f"{base}/providers/Microsoft.Network/networkSecurityGroups", params={"api-version": api["network"]}, headers=headers)
            for nsg in resp.json().get("value", []):
                name = nsg["name"]
                for rule in nsg.get("properties", {}).get("securityRules", []):
                    rp = rule.get("properties", {})
                    if rp.get("access") != "Allow" or rp.get("direction") != "Inbound":
                        continue
                    src = rp.get("sourceAddressPrefix", "")
                    if src not in ("*", "0.0.0.0/0", "Internet", "Any"):
                        continue
                    port_range = rp.get("destinationPortRange", "")
                    if check_id == "azure_nsg_open_ssh" and port_range in ("22", "*"):
                        findings.append(_finding(name, nsg["id"], f"NSG {name} allows SSH from any source.", "critical"))
                    elif check_id == "azure_nsg_open_rdp" and port_range in ("3389", "*"):
                        findings.append(_finding(name, nsg["id"], f"NSG {name} allows RDP from any source.", "critical"))
                    elif check_id == "azure_nsg_open_all" and port_range == "*" and rp.get("protocol") == "*":
                        findings.append(_finding(name, nsg["id"], f"NSG {name} allows all traffic from any source.", "critical"))

        elif check_id.startswith("azure_sql_"):
            servers_resp = await client.get(f"{base}/providers/Microsoft.Sql/servers", params={"api-version": api["sql"]}, headers=headers)
            for server in servers_resp.json().get("value", []):
                sname = server["name"]
                if check_id == "azure_sql_public_network":
                    if server.get("properties", {}).get("publicNetworkAccess") == "Enabled":
                        findings.append(_finding(sname, server["id"], f"SQL server {sname} allows public network access.", "critical"))
                elif check_id == "azure_sql_no_tde":
                    try:
                        rg = server["id"].split("/resourceGroups/")[1].split("/")[0]
                        dbs_resp = await client.get(
                            f"{base}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{sname}/databases",
                            params={"api-version": api["sql"]}, headers=headers,
                        )
                        for db in dbs_resp.json().get("value", []):
                            if db["name"] == "master":
                                continue
                            tde_resp = await client.get(
                                f"{base}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{sname}/databases/{db['name']}/transparentDataEncryption/current",
                                params={"api-version": api["sql"]}, headers=headers,
                            )
                            if tde_resp.status_code == 200 and tde_resp.json().get("properties", {}).get("state") != "Enabled":
                                findings.append(_finding(db["name"], db["id"], f"Database {db['name']} on {sname} does not have TDE enabled.", "high"))
                    except Exception:
                        continue

        elif check_id == "azure_keyvault_no_soft_delete":
            resp = await client.get(f"{base}/providers/Microsoft.KeyVault/vaults", params={"api-version": api["vault"]}, headers=headers)
            for vault in resp.json().get("value", []):
                name = vault["name"]
                props = vault.get("properties", {})
                if not props.get("enableSoftDelete") or not props.get("enablePurgeProtection"):
                    findings.append(_finding(name, vault["id"], f"Key Vault {name} does not have soft-delete and purge protection both enabled.", "high"))

        elif check_id == "azure_vm_no_disk_encryption":
            resp = await client.get(f"{base}/providers/Microsoft.Compute/virtualMachines", params={"api-version": api["compute"]}, headers=headers)
            for vm in resp.json().get("value", []):
                name = vm["name"]
                enc = vm.get("properties", {}).get("storageProfile", {}).get("osDisk", {}).get("encryptionSettings", {})
                if not enc.get("enabled"):
                    findings.append(_finding(name, vm["id"], f"VM {name} does not have OS disk encryption enabled.", "medium"))

    except Exception:
        pass

    return findings


# ── Kubernetes checks (raw REST against the API server — no client library) ──

K8S_CHECKS: list[dict] = [
    {"id": "k8s_anonymous_auth",           "name": "API Server Allows Anonymous Authentication",   "severity": "critical", "category": "Cluster"},
    {"id": "k8s_privileged_pods",          "name": "Privileged Pod Detected",                      "severity": "critical", "category": "Workloads"},
    {"id": "k8s_hostpath_mounts",          "name": "Pod Mounts hostPath Volume",                   "severity": "high",     "category": "Workloads"},
    {"id": "k8s_default_sa_automount",     "name": "Default ServiceAccount Token Auto-Mounted",    "severity": "medium",   "category": "Workloads"},
    {"id": "k8s_clusterrolebinding_broad", "name": "ClusterRoleBinding Grants cluster-admin Broadly", "severity": "critical", "category": "RBAC"},
    {"id": "k8s_missing_network_policy",   "name": "Namespace Has No NetworkPolicy",               "severity": "medium",   "category": "Network"},
    {"id": "k8s_secrets_in_env",           "name": "Pod References Secret via Environment Variable", "severity": "low",    "category": "Workloads"},
    {"id": "k8s_host_network",             "name": "Pod Uses hostNetwork",                         "severity": "high",     "category": "Workloads"},
]

_K8S_REMEDIATION: dict[str, str] = {
    "k8s_anonymous_auth":           "Disable anonymous authentication on the API server (--anonymous-auth=false).",
    "k8s_privileged_pods":          "Remove privileged: true from the container securityContext; use fine-grained capabilities instead.",
    "k8s_hostpath_mounts":          "Avoid hostPath volumes; use PersistentVolumeClaims or a CSI driver.",
    "k8s_default_sa_automount":     "Set automountServiceAccountToken: false unless the workload needs API access.",
    "k8s_clusterrolebinding_broad": "Scope the RoleBinding to a namespace and specific subjects instead of cluster-admin.",
    "k8s_missing_network_policy":   "Add a default-deny NetworkPolicy and allow only required traffic.",
    "k8s_secrets_in_env":           "Mount secrets as files instead of environment variables to reduce leak surface (process listing, logs).",
    "k8s_host_network":             "Remove hostNetwork: true unless strictly required; it exposes the node's network namespace.",
}


async def _run_k8s_check(check_id: str, client: "httpx.AsyncClient") -> list[dict]:
    """Execute a single Kubernetes check via the raw API server REST interface."""
    findings: list[dict] = []

    def _finding(resource: str, resource_id: str, description: str, severity: str) -> dict:
        return {
            "check_id": check_id,
            "severity": severity,
            "resource": resource,
            "resource_arn": resource_id,
            "description": description,
            "remediation": _K8S_REMEDIATION.get(check_id, "Review Kubernetes security best practices."),
        }

    try:
        if check_id == "k8s_anonymous_auth":
            # An unauthenticated request that gets anything other than 401/403 indicates
            # anonymous auth is permitted for at least some resources.
            resp = await client.get("/api/v1/namespaces", headers={})
            if resp.status_code == 200:
                findings.append(_finding("kube-apiserver", "cluster", "The API server answered an unauthenticated request — anonymous auth appears enabled.", "critical"))

        elif check_id in ("k8s_privileged_pods", "k8s_hostpath_mounts", "k8s_default_sa_automount", "k8s_secrets_in_env", "k8s_host_network"):
            resp = await client.get("/api/v1/pods")
            if resp.status_code != 200:
                return findings
            for pod in resp.json().get("items", []):
                ns = pod["metadata"]["namespace"]
                name = pod["metadata"]["name"]
                spec = pod.get("spec", {})
                ref = f"{ns}/{name}"

                if check_id == "k8s_privileged_pods":
                    for c in spec.get("containers", []):
                        if c.get("securityContext", {}).get("privileged"):
                            findings.append(_finding(ref, ref, f"Pod {ref} runs container '{c['name']}' as privileged.", "critical"))

                elif check_id == "k8s_hostpath_mounts":
                    for v in spec.get("volumes", []):
                        if "hostPath" in v:
                            findings.append(_finding(ref, ref, f"Pod {ref} mounts hostPath volume '{v.get('name')}' ({v['hostPath'].get('path')}).", "high"))

                elif check_id == "k8s_default_sa_automount":
                    if spec.get("serviceAccountName", "default") == "default" and spec.get("automountServiceAccountToken", True):
                        findings.append(_finding(ref, ref, f"Pod {ref} auto-mounts the default ServiceAccount token.", "medium"))

                elif check_id == "k8s_secrets_in_env":
                    for c in spec.get("containers", []):
                        for env in c.get("env", []):
                            if env.get("valueFrom", {}).get("secretKeyRef"):
                                findings.append(_finding(ref, ref, f"Pod {ref} container '{c['name']}' injects a secret via environment variable '{env['name']}'.", "low"))

                elif check_id == "k8s_host_network":
                    if spec.get("hostNetwork"):
                        findings.append(_finding(ref, ref, f"Pod {ref} uses hostNetwork.", "high"))

        elif check_id == "k8s_clusterrolebinding_broad":
            resp = await client.get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
            if resp.status_code != 200:
                return findings
            for crb in resp.json().get("items", []):
                role_ref = crb.get("roleRef", {})
                if role_ref.get("name") != "cluster-admin":
                    continue
                for subject in crb.get("subjects", []) or []:
                    if subject.get("kind") == "Group" and subject.get("name") in ("system:authenticated", "system:unauthenticated", "system:anonymous"):
                        name = crb["metadata"]["name"]
                        findings.append(_finding(name, name, f"ClusterRoleBinding {name} grants cluster-admin to '{subject.get('name')}'.", "critical"))

        elif check_id == "k8s_missing_network_policy":
            ns_resp = await client.get("/api/v1/namespaces")
            np_resp = await client.get("/apis/networking.k8s.io/v1/networkpolicies")
            if ns_resp.status_code != 200 or np_resp.status_code != 200:
                return findings
            namespaces_with_np = {np["metadata"]["namespace"] for np in np_resp.json().get("items", [])}
            for ns in ns_resp.json().get("items", []):
                ns_name = ns["metadata"]["name"]
                if ns_name in ("kube-system", "kube-public", "kube-node-lease"):
                    continue
                if ns_name not in namespaces_with_np:
                    findings.append(_finding(ns_name, ns_name, f"Namespace {ns_name} has no NetworkPolicy defined.", "medium"))

    except Exception:
        pass

    return findings


# ── Prowler integration ───────────────────────────────────────────────────────

async def _run_prowler(req: CSPMScanRequest) -> list[dict] | None:
    """Run Prowler CLI if available and return findings in our format."""
    if not shutil.which("prowler"):
        return None
    import tempfile, os, subprocess  # noqa: E401

    out_dir = tempfile.mkdtemp(prefix="prowler_")
    env = os.environ.copy()
    if req.aws_access_key:
        env["AWS_ACCESS_KEY_ID"] = req.aws_access_key
    if req.aws_secret_key:
        env["AWS_SECRET_ACCESS_KEY"] = req.aws_secret_key
    if req.aws_session_token:
        env["AWS_SESSION_TOKEN"] = req.aws_session_token
    if req.aws_region:
        env["AWS_DEFAULT_REGION"] = req.aws_region

    cmd = ["prowler", "aws", "-M", "json", "-o", out_dir, "--filter-severity", "critical", "high", "medium"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=600)
    except Exception:
        return None

    # Find the JSON output file
    findings: list[dict] = []
    try:
        import glob as _glob
        for jf in _glob.glob(f"{out_dir}/**/*.json", recursive=True):
            raw = json.loads(Path(jf).read_text(errors="replace"))
            items = raw if isinstance(raw, list) else raw.get("results", [])
            for item in items:
                status = (item.get("Status") or item.get("status", "")).upper()
                if status != "FAIL":
                    continue
                severity = (item.get("Severity") or item.get("severity", "medium")).lower()
                findings.append({
                    "check_id": item.get("CheckID") or item.get("check_id", "prowler_check"),
                    "severity": severity,
                    "resource": item.get("ResourceId") or item.get("resource", "unknown"),
                    "resource_arn": item.get("ResourceArn") or item.get("resource_arn", ""),
                    "description": item.get("Description") or item.get("description", ""),
                    "remediation": item.get("Remediation", {}).get("Recommendation", {}).get("Text", "") if isinstance(item.get("Remediation"), dict) else str(item.get("Remediation", "")),
                })
    except Exception:
        pass

    try:
        import shutil as _sh
        _sh.rmtree(out_dir, ignore_errors=True)
    except Exception:
        pass

    return findings


# ── Severity filter helper ────────────────────────────────────────────────────

def _above_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER.get(threshold, 99)


# ── SSE stream generator ──────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


_ALL_CHECK_NAMES: dict[str, str] = {
    c["id"]: c["name"] for c in (AWS_CHECKS + GCP_CHECKS + AZURE_CHECKS + K8S_CHECKS)
}


def _adapt_cspm_findings(provider: str, findings: list[dict]) -> list[dict]:
    """Normalize CSPM findings for app.services.finding_ingest.ingest_findings.

    Confidence is "certain" — every CSPM check reads the resource's live state
    directly from the cloud provider's own API (boto3 / REST), not an inference.
    """
    adapted = []
    for f in findings:
        check_id = f.get("check_id", "")
        adapted.append({
            "title": _ALL_CHECK_NAMES.get(check_id, f.get("description", "CSPM finding")),
            "description": f.get("description", ""),
            "severity": f.get("severity", "medium"),
            "category": f"cspm-{provider}",
            "affected_asset": f.get("resource_arn") or f.get("resource", ""),
            "evidence": {"check_id": check_id, "resource": f.get("resource"), "resource_arn": f.get("resource_arn")},
            "remediation": f.get("remediation", ""),
            "confidence": "certain",
        })
    return adapted


async def _cspm_stream(
    scan_id: str,
    req: CSPMScanRequest,
    org_id: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    started = time.time()
    all_findings: list[dict] = []
    checks_run = 0
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # ── Determine which checks to run ────────────────────────────────────────
    _CATALOGUE = {"aws": AWS_CHECKS, "gcp": GCP_CHECKS, "azure": AZURE_CHECKS, "kubernetes": K8S_CHECKS}
    catalogue = _CATALOGUE.get(req.provider)
    if catalogue is None:
        yield _sse("error", {"message": f"Unknown provider '{req.provider}'"})
        return
    checks = [c for c in catalogue if not req.categories or c["category"] in req.categories]

    # ── Try Prowler first (AWS only) ─────────────────────────────────────────
    prowler_findings = None
    if shutil.which("prowler") and req.provider == "aws":
        yield _sse("status", {"message": "Prowler CLI detected — running full Prowler scan..."})
        prowler_findings = await _run_prowler(req)

    if prowler_findings is not None:
        # Emit Prowler findings grouped by check
        for f in prowler_findings:
            if _above_threshold(f["severity"], req.severity_filter):
                yield _sse("finding", f)
                all_findings.append(f)
                by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        checks_run = len(checks)

    elif req.provider == "aws":
        # ── Native boto3 checks ───────────────────────────────────────────────
        if not _BOTO3_AVAILABLE:
            yield _sse("error", {"message": "boto3 is not installed. Run: pip install boto3"})
            return

        try:
            session = _make_boto_session(req)
        except Exception as exc:
            yield _sse("error", {"message": f"Failed to create AWS session: {exc}"})
            return

        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=6)

        async def _run_check_async(check: dict) -> list[dict]:
            return await loop.run_in_executor(executor, _run_aws_check, check["id"], session)

        # Run checks in batches of 5 concurrently
        BATCH = 5
        for i in range(0, len(checks), BATCH):
            batch = checks[i : i + BATCH]
            # Announce start of each check in the batch
            for c in batch:
                yield _sse("check_start", {"check_id": c["id"], "check_name": c["name"]})

            results = await asyncio.gather(*[_run_check_async(c) for c in batch])

            for c, raw_findings in zip(batch, results):
                batch_findings = [f for f in raw_findings if _above_threshold(f["severity"], req.severity_filter)]
                for f in batch_findings:
                    yield _sse("finding", f)
                    all_findings.append(f)
                    by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
                yield _sse("check_complete", {"check_id": c["id"], "findings_count": len(batch_findings)})
                checks_run += 1

        executor.shutdown(wait=False)

    elif req.provider == "gcp":
        if not req.gcp_project_id or not req.gcp_service_account_key:
            yield _sse("error", {"message": "gcp_project_id and gcp_service_account_key are required"})
            return
        try:
            loop = asyncio.get_event_loop()
            token = await loop.run_in_executor(None, _gcp_access_token, req.gcp_service_account_key)
        except Exception as exc:
            yield _sse("error", {"message": f"Failed to authenticate with GCP: {exc}"})
            return

        async with httpx.AsyncClient(timeout=30.0) as client:
            BATCH = 3
            for i in range(0, len(checks), BATCH):
                batch = checks[i : i + BATCH]
                for c in batch:
                    yield _sse("check_start", {"check_id": c["id"], "check_name": c["name"]})
                results = await asyncio.gather(
                    *[_run_gcp_check(c["id"], req.gcp_project_id, token, client) for c in batch]
                )
                for c, raw_findings in zip(batch, results):
                    batch_findings = [f for f in raw_findings if _above_threshold(f["severity"], req.severity_filter)]
                    for f in batch_findings:
                        yield _sse("finding", f)
                        all_findings.append(f)
                        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
                    yield _sse("check_complete", {"check_id": c["id"], "findings_count": len(batch_findings)})
                    checks_run += 1

    elif req.provider == "azure":
        if not all([req.azure_subscription_id, req.azure_tenant_id, req.azure_client_id, req.azure_client_secret]):
            yield _sse("error", {"message": "azure_subscription_id, azure_tenant_id, azure_client_id, and azure_client_secret are required"})
            return

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                token = await _azure_access_token(req.azure_tenant_id, req.azure_client_id, req.azure_client_secret, client)
            except Exception as exc:
                yield _sse("error", {"message": f"Failed to authenticate with Azure: {exc}"})
                return

            BATCH = 3
            for i in range(0, len(checks), BATCH):
                batch = checks[i : i + BATCH]
                for c in batch:
                    yield _sse("check_start", {"check_id": c["id"], "check_name": c["name"]})
                results = await asyncio.gather(
                    *[_run_azure_check(c["id"], req.azure_subscription_id, token, client) for c in batch]
                )
                for c, raw_findings in zip(batch, results):
                    batch_findings = [f for f in raw_findings if _above_threshold(f["severity"], req.severity_filter)]
                    for f in batch_findings:
                        yield _sse("finding", f)
                        all_findings.append(f)
                        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
                    yield _sse("check_complete", {"check_id": c["id"], "findings_count": len(batch_findings)})
                    checks_run += 1

    elif req.provider == "kubernetes":
        if not req.k8s_api_server or not req.k8s_token:
            yield _sse("error", {"message": "k8s_api_server and k8s_token are required"})
            return

        # Default: verify against the system trust store (safe for a properly-issued
        # or already-trusted cert). A pasted CA cert pins verification to it. Skipping
        # verification entirely requires the caller's explicit opt-in — never a silent
        # default, since that would allow a MITM to intercept cluster credentials.
        verify: bool | str = True
        ca_temp_path = None
        if req.k8s_ca_cert:
            import tempfile
            fd, ca_temp_path = tempfile.mkstemp(suffix=".pem")
            with __import__("os").fdopen(fd, "w") as f:
                f.write(req.k8s_ca_cert)
            verify = ca_temp_path
        elif req.k8s_insecure_skip_tls_verify:
            verify = False

        try:
            async with httpx.AsyncClient(
                base_url=req.k8s_api_server.rstrip("/"),
                headers={"Authorization": f"Bearer {req.k8s_token}"},
                timeout=30.0,
                verify=verify,
            ) as client:
                # Preflight: fail loudly on connection/auth errors rather than letting
                # every per-check broad `except` silently produce a false "0 findings".
                try:
                    preflight = await client.get("/api")
                    if preflight.status_code in (401, 403):
                        yield _sse("error", {"message": f"Kubernetes API server rejected the token ({preflight.status_code})"})
                        return
                except httpx.HTTPError as exc:
                    yield _sse("error", {"message": f"Could not reach Kubernetes API server: {exc}"})
                    return

                BATCH = 3
                for i in range(0, len(checks), BATCH):
                    batch = checks[i : i + BATCH]
                    for c in batch:
                        yield _sse("check_start", {"check_id": c["id"], "check_name": c["name"]})
                    results = await asyncio.gather(*[_run_k8s_check(c["id"], client) for c in batch])
                    for c, raw_findings in zip(batch, results):
                        batch_findings = [f for f in raw_findings if _above_threshold(f["severity"], req.severity_filter)]
                        for f in batch_findings:
                            yield _sse("finding", f)
                            all_findings.append(f)
                            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
                        yield _sse("check_complete", {"check_id": c["id"], "findings_count": len(batch_findings)})
                        checks_run += 1
        finally:
            if ca_temp_path:
                try:
                    __import__("os").unlink(ca_temp_path)
                except OSError:
                    pass

    # ── Save to history ───────────────────────────────────────────────────────
    duration = round(time.time() - started, 1)
    record = {
        "id": scan_id,
        "provider": req.provider,
        "region": req.aws_region if req.provider == "aws" else None,
        "categories": req.categories,
        "severity_filter": req.severity_filter,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "checks_run": checks_run,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "findings": all_findings,
        "prowler_used": prowler_findings is not None,
    }
    _save_scan_result(org_id, record)

    try:
        adapted = _adapt_cspm_findings(req.provider, all_findings)
        await ingest_findings(db, org_id, source="cspm", source_scan_id=scan_id, findings=adapted)
        await db.commit()
    except Exception:
        await db.rollback()

    yield _sse("complete", {
        "scan_id": scan_id,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "checks_run": checks_run,
        "duration_seconds": duration,
        "prowler_used": prowler_findings is not None,
    })


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/history", summary="List CSPM scan history")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    records = _load_history(str(org_id))
    # Strip findings list from summary response for performance
    summaries = [
        {k: v for k, v in r.items() if k != "findings"}
        for r in records
    ]
    return {"items": summaries, "total": len(summaries)}


@router.get("/history/{scan_id}", summary="Get single CSPM scan")
async def get_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete CSPM scan")
async def delete_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    ok = _delete_scan(str(org_id), scan_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}


@router.get("/checks", summary="List available CSPM check categories")
async def list_checks(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    provider: str = "aws",
) -> dict:
    catalogue = {"aws": AWS_CHECKS, "gcp": GCP_CHECKS, "azure": AZURE_CHECKS, "kubernetes": K8S_CHECKS}.get(provider)
    if catalogue is None:
        raise HTTPException(status_code=400, detail="provider must be one of: aws, azure, gcp, kubernetes")
    return {
        "provider": provider,
        "categories": sorted({c["category"] for c in catalogue}),
        "checks": catalogue,
        "total": len(catalogue),
    }


@router.post("/scan", summary="Start a CSPM scan (SSE stream)")
async def start_scan(
    req: CSPMScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    if req.provider not in ("aws", "azure", "gcp", "kubernetes"):
        raise HTTPException(status_code=400, detail="provider must be one of: aws, azure, gcp, kubernetes")

    scan_id = str(_uuid_mod.uuid4())

    return StreamingResponse(
        _cspm_stream(scan_id, req, str(org_id), db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-Scan-Id": scan_id,
        },
    )
